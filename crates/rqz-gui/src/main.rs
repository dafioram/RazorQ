//! razerq desktop app. Health first: opening an archive shows whether it is healthy,
//! repairable or damaged, how much protection is left, and where the damage is.

use eframe::egui::{self, Color32, RichText};
use rqz_core::archive::{Archive, Assessment, BlockState, Health, Info};
use rqz_core::codec::Compression;
use rqz_core::fsops::{self, Source};
use rqz_core::index::{FileEntry, KIND_FILE};
use rqz_core::progress::{Event, Progress};
use rqz_core::writer::{PackOptions, Protect};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};

const GREEN: Color32 = Color32::from_rgb(64, 178, 108);
const AMBER: Color32 = Color32::from_rgb(232, 164, 48);
const RED: Color32 = Color32::from_rgb(214, 76, 76);
const MUTED: Color32 = Color32::from_rgb(140, 148, 160);

struct Opened {
    path: PathBuf,
    archive: Arc<Archive<Source>>,
    assessment: Assessment,
    info: Info,
    password: Option<String>,
}

enum Msg {
    Progress(Event),
    Opened(Result<Box<Opened>, String>),
    Finished { text: String, ok: bool, open: Option<(PathBuf, Option<String>)> },
}

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Files,
    Health,
    New,
}

struct App {
    tab: Tab,
    opened: Option<Opened>,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    busy: Option<(String, f32)>,
    banner: Option<(String, bool)>,
    filter: String,
    snapshot: Option<u32>,
    // new-archive form
    inputs: Vec<PathBuf>,
    input_bytes: u64,
    protect_pct: f32,
    compression: usize,
    encrypt: bool,
    password: String,
    // password prompt for locked archives
    unlock: Option<String>,
}

fn human(n: u64) -> String {
    let u = ["B", "KB", "MB", "GB", "TB"];
    let (mut v, mut i) = (n as f64, 0);
    while v >= 1000.0 && i < 4 {
        v /= 1000.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", u[i])
    }
}

impl App {
    fn new() -> App {
        let (tx, rx) = channel();
        App {
            tab: Tab::Files,
            opened: None,
            tx,
            rx,
            busy: None,
            banner: None,
            filter: String::new(),
            snapshot: None,
            inputs: vec![],
            input_bytes: 0,
            protect_pct: 10.0,
            compression: 2,
            encrypt: false,
            password: String::new(),
            unlock: None,
        }
    }

    /// Run `f` on a worker thread, streaming progress back to the UI.
    fn spawn(&mut self, ctx: &egui::Context, label: &str, f: impl FnOnce(&dyn Progress) -> Msg + Send + 'static) {
        self.busy = Some((label.to_string(), 0.0));
        self.banner = None;
        let tx = Mutex::new(self.tx.clone());
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let prog = |e: Event| {
                let _ = tx.lock().unwrap().send(Msg::Progress(e));
                ctx.request_repaint();
            };
            let msg = f(&prog);
            let _ = tx.lock().unwrap().send(msg);
            ctx.request_repaint();
        });
    }

    fn open(&mut self, ctx: &egui::Context, path: PathBuf, password: Option<String>) {
        self.spawn(ctx, "Opening", move |p| {
            let r = (|| -> Result<Box<Opened>, String> {
                let a = Archive::open(Source::open(&path).map_err(|e| e.to_string())?, password.as_deref())
                    .map_err(|e| e.to_string())?;
                let (a, _) = if a.index.detached.is_some() {
                    fsops::open_any(&path, password.as_deref(), None).map_err(|e| e.to_string())?
                } else {
                    (a, None)
                };
                let assessment = a.assess(p);
                let info = a.info();
                Ok(Box::new(Opened { path: path.clone(), archive: Arc::new(a), assessment, info, password }))
            })();
            Msg::Opened(r)
        });
    }

    fn poll(&mut self, ctx: &egui::Context) {
        while let Ok(m) = self.rx.try_recv() {
            match m {
                Msg::Progress(Event::Progress { done, total }) => {
                    if let Some(b) = &mut self.busy {
                        b.1 = if total > 0 { (done as f32 / total as f32).clamp(0.0, 1.0) } else { 0.0 };
                    }
                }
                Msg::Progress(Event::Stage(s)) => {
                    if let Some(b) = &mut self.busy {
                        b.0 = s;
                        b.1 = 0.0;
                    }
                }
                Msg::Progress(Event::Note(_)) => {}
                Msg::Opened(r) => {
                    self.busy = None;
                    match r {
                        Ok(o) => {
                            self.snapshot = None;
                            self.unlock = o.archive.locked.then(String::new);
                            self.opened = Some(*o);
                            self.tab = Tab::Files;
                        }
                        Err(e) => {
                            self.banner = Some((e, false));
                            if self.opened.as_ref().is_some_and(|o| o.archive.locked) {
                                self.unlock = Some(String::new());
                            }
                        }
                    }
                }
                Msg::Finished { text, ok, open } => {
                    self.busy = None;
                    self.banner = Some((text, ok));
                    if let Some((p, pw)) = open {
                        let banner = self.banner.take();
                        self.open(ctx, p, pw);
                        self.banner = banner;
                    }
                }
            }
        }
    }

    fn pick_open(&mut self, ctx: &egui::Context) {
        if let Some(p) = rfd::FileDialog::new().set_title("Open an archive, sidecar, or volume").pick_file() {
            self.open(ctx, p, None);
        }
    }

    fn add_inputs(&mut self, paths: Vec<PathBuf>) {
        for p in paths {
            if !self.inputs.contains(&p) {
                self.inputs.push(p);
            }
        }
        self.input_bytes = fsops::collect(&self.inputs, None).map(|(_, t)| t).unwrap_or(0);
        self.tab = Tab::New;
    }

    fn header_card(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let Some(o) = &self.opened else { return };
        let (color, title) = match o.assessment.health {
            Health::Healthy if o.assessment.stored_bytes_only => (GREEN, "Stored bytes healthy (locked)"),
            Health::Healthy => (GREEN, "Healthy"),
            Health::Repairable => (AMBER, "Repairable"),
            Health::Damaged => (RED, "Damaged beyond recovery"),
        };
        let lost = o.assessment.block_states.iter().filter(|s| **s == BlockState::Lost).count();
        let low = o.assessment.min_headroom_ratio.map(|r| r < 0.02).unwrap_or(false);
        let (color, title) = if o.assessment.health == Health::Healthy && low && !o.assessment.stored_bytes_only {
            (AMBER, "Healthy, but nearly out of protection")
        } else {
            (color, title)
        };
        let detail = match o.assessment.health {
            Health::Healthy => format!("{} blocks verified.", o.assessment.blocks_total),
            Health::Repairable => format!(
                "{} of {} blocks damaged; all recoverable.",
                o.assessment.blocks_damaged, o.assessment.blocks_total
            ),
            Health::Damaged if !o.assessment.inventory_complete && !o.assessment.stored_bytes_only => {
                format!("Complete file inventory unavailable. {lost} known block(s) could not be recovered.")
            }
            Health::Damaged => format!("{lost} blocks could not be recovered with the available recovery data."),
        };
        let spare = match o.assessment.min_headroom_ratio {
            Some(r) => format!(
                "Tightest group: {:.1}% headroom · minimum {} spare symbol(s).",
                r * 100.0,
                o.assessment.min_headroom_symbols.unwrap_or(0)
            ),
            None => "No recovery data: damage can be detected but not repaired.".into(),
        };
        let path = o.path.clone();
        let extract_available = !o.info.detached && !o.info.locked;
        let detached = o.info.detached;
        let health = o.assessment.health;
        let weak = o.info.weak_protection.clone();
        let notes = o.assessment.structural.clone();
        egui::Frame::new()
            .fill(color.gamma_multiply(0.16))
            .stroke(egui::Stroke::new(1.0_f32, color))
            .corner_radius(8.0)
            .inner_margin(14.0)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("●").color(color).size(22.0));
                    ui.vertical(|ui| {
                        ui.label(RichText::new(title).size(20.0).strong());
                        ui.label(detail);
                        ui.label(RichText::new(spare).color(MUTED));
                        if let Some(w) = &weak {
                            ui.label(RichText::new(format!("⚠ {w}")).color(AMBER));
                        }
                        for n in &notes {
                            ui.label(RichText::new(format!("• {n}")).color(MUTED));
                        }
                    });
                });
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if health != Health::Healthy && self.busy.is_none() && ui.button("Save repaired copy…").clicked()
                    {
                        self.start_repair(ctx, &path, None);
                    }
                    if health == Health::Damaged
                        && self.busy.is_none()
                        && ui.button("Repair using another copy…").clicked()
                    {
                        if let Some(d) = rfd::FileDialog::new().pick_file() {
                            self.start_repair(ctx, &path, Some(d));
                        }
                    }
                    if !detached
                        && ui
                            .add_enabled(
                                self.busy.is_none() && extract_available,
                                egui::Button::new(if health == Health::Damaged {
                                    "Extract what's intact…"
                                } else {
                                    "Extract all…"
                                }),
                            )
                            .clicked()
                    {
                        self.start_extract(ctx);
                    }
                });
            });
    }

    fn start_repair(&mut self, ctx: &egui::Context, path: &Path, donor: Option<PathBuf>) {
        let split = self.opened.as_ref().map(|o| o.archive.source().is_split()).unwrap_or(false);
        // A split archive is repaired into a folder of volumes; a single file into one new file.
        let detached = self.opened.as_ref().and_then(|o| o.archive.index.detached.as_ref());
        let picked = if split {
            rfd::FileDialog::new().set_title("Choose a folder for the repaired volumes").pick_folder()
        } else {
            rfd::FileDialog::new()
                .set_file_name(
                    fsops::repaired_name(detached.map(|d| Path::new(&d.target_name)).unwrap_or(path))
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy(),
                )
                .save_file()
        };
        let Some(out) = picked else { return };
        let (path, pw) = (path.to_path_buf(), self.opened.as_ref().and_then(|o| o.password.clone()));
        let detached_archive = detached.is_some();
        self.spawn(ctx, "Repairing", move |p| {
            let opts =
                fsops::RepairOptions { out: Some(out.clone()), donor, password: pw.clone(), ..Default::default() };
            match fsops::repair_file(&path, &opts, p) {
                Ok(r) => {
                    let status = match r.exit_code() {
                        0 => "Nothing to repair.",
                        1 if r.stored_bytes_only => "Repair verified for stored bytes. Unlock to verify files.",
                        1 => "Repair verified.",
                        _ => "Repair incomplete.",
                    };
                    let mut details = vec![status.to_owned()];
                    details.extend(r.outputs.iter().map(|p| format!("Wrote {}", p.display())));
                    if !r.plan.lost_blocks.is_empty() {
                        details.push(format!("{} unrecovered block(s).", r.plan.lost_blocks.len()));
                    }
                    details.extend(r.plan.lost_files.iter().take(5).map(|f| format!("Lost: {f}")));
                    details.extend(r.plan.notes.iter().cloned());
                    Msg::Finished {
                        text: details.join(" "),
                        ok: r.exit_code() < 2,
                        open: if detached_archive { None } else { r.archive_output.map(|p| (p, pw)) },
                    }
                }
                Err(e) => Msg::Finished { text: e.to_string(), ok: false, open: None },
            }
        });
    }

    fn start_extract(&mut self, ctx: &egui::Context) {
        let Some(o) = &self.opened else { return };
        let Some(dest) = rfd::FileDialog::new().pick_folder() else { return };
        let (a, snap) = (o.archive.clone(), self.snapshot);
        self.spawn(ctx, "Extracting", move |p| match fsops::extract_archive(&a, &dest, &[], snap, p) {
            Ok(r) => {
                let mut t = format!("Extracted {} files ({}).", r.files, human(r.bytes));
                if r.healed_groups > 0 {
                    t += &format!(" Repaired {} damaged group(s) in memory.", r.healed_groups);
                }
                if !r.lost.is_empty() {
                    t += &format!(" Lost to damage: {}.", r.lost.join(", "));
                }
                if !r.skipped.is_empty() {
                    t += &format!(" Skipped: {}.", r.skipped.join(", "));
                }
                if !r.inventory_complete {
                    t += " Complete file inventory unavailable.";
                }
                Msg::Finished {
                    text: t,
                    ok: r.lost.is_empty() && r.skipped.is_empty() && r.inventory_complete,
                    open: None,
                }
            }
            Err(e) => Msg::Finished { text: e.to_string(), ok: false, open: None },
        });
    }

    fn files_tab(&mut self, ui: &mut egui::Ui) {
        let Some(o) = &self.opened else { return };
        if o.info.detached {
            ui.label("This is a sidecar: it holds recovery data for a separate file.");
            return;
        }
        if o.archive.locked {
            ui.label(RichText::new("File names are encrypted. Enter the password to browse.").color(MUTED));
            return;
        }
        ui.horizontal(|ui| {
            ui.label("Filter");
            ui.text_edit_singleline(&mut self.filter);
            if o.info.snapshots.len() > 1 {
                egui::ComboBox::from_label("Snapshot")
                    .selected_text(self.snapshot.map(|s| format!("as of #{s}")).unwrap_or_else(|| "latest".into()))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.snapshot, None, "latest");
                        for s in &o.info.snapshots {
                            ui.selectable_value(&mut self.snapshot, Some(s.id), format!("#{} {}", s.id, s.name));
                        }
                    });
            }
        });
        let q = self.filter.to_lowercase();
        let files: Vec<&FileEntry> = o
            .archive
            .visible_files(self.snapshot)
            .into_iter()
            .filter(|f| f.kind == KIND_FILE && (q.is_empty() || f.path.to_lowercase().contains(&q)))
            .collect();
        ui.label(RichText::new(format!("{} files", files.len())).color(MUTED));
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            egui::Grid::new("files").striped(true).num_columns(2).show(ui, |ui| {
                for f in files.iter().take(5000) {
                    ui.label(&f.path);
                    ui.label(RichText::new(human(f.size)).color(MUTED));
                    ui.end_row();
                }
            });
        });
    }

    fn health_tab(&mut self, ui: &mut egui::Ui) {
        let Some(o) = &self.opened else { return };
        let a = &o.assessment;
        ui.label(RichText::new("Block map").strong());
        ui.label(
            RichText::new("Position in the file. Green = intact, amber = damaged but recoverable, red = lost.")
                .color(MUTED),
        );
        let n = a.block_states.len();
        if n > 0 {
            let per = n.div_ceil(2400);
            let cells = n.div_ceil(per);
            let width = ui.available_width();
            let cell = 11.0f32;
            let cols = ((width / (cell + 2.0)) as usize).max(1);
            let rows = cells.div_ceil(cols);
            let (rect, _) = ui.allocate_exact_size(egui::vec2(width, rows as f32 * (cell + 2.0)), egui::Sense::hover());
            let painter = ui.painter_at(rect);
            for (c, slice) in a.block_states.chunks(per).enumerate() {
                let color = if slice.contains(&BlockState::Lost) {
                    RED
                } else if slice.contains(&BlockState::Repairable) {
                    AMBER
                } else {
                    GREEN
                };
                let (x, y) = ((c % cols) as f32 * (cell + 2.0), (c / cols) as f32 * (cell + 2.0));
                painter.rect_filled(
                    egui::Rect::from_min_size(rect.min + egui::vec2(x, y), egui::vec2(cell, cell)),
                    2.0,
                    color,
                );
            }
            if per > 1 {
                ui.label(RichText::new(format!("Each square covers {per} blocks.")).color(MUTED));
            }
        }
        ui.add_space(10.0);
        ui.label(RichText::new("Protection headroom per group").strong());
        ui.label(
            RichText::new("Striping spreads damage across groups. The tightest groups are the ones that matter.")
                .color(MUTED),
        );
        let mut groups: Vec<_> = a.groups.iter().collect();
        groups.sort_by_key(|g| g.headroom());
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            for g in groups.iter().take(24) {
                let total = g.repair_total.max(1) as f32;
                let frac = (g.headroom().max(0) as f32 / total).clamp(0.0, 1.0);
                let color = if g.headroom() < 0 {
                    RED
                } else if frac < 0.3 {
                    AMBER
                } else {
                    GREEN
                };
                ui.horizontal(|ui| {
                    ui.label(format!("set {} · group {}", g.set, g.group));
                    ui.add(egui::ProgressBar::new(frac).fill(color).desired_width(220.0).text(format!(
                        "{} spare · {} erased",
                        g.headroom(),
                        g.erased
                    )));
                });
            }
            if groups.is_empty() {
                ui.label(RichText::new("No recovery groups in this archive.").color(MUTED));
            }
        });
    }

    fn new_tab(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.label(RichText::new("New archive").size(18.0).strong());
        ui.label(RichText::new("Drop files or folders anywhere in this window, or add them below.").color(MUTED));
        ui.horizontal(|ui| {
            if ui.button("Add files…").clicked() {
                if let Some(p) = rfd::FileDialog::new().pick_files() {
                    self.add_inputs(p);
                }
            }
            if ui.button("Add folder…").clicked() {
                if let Some(p) = rfd::FileDialog::new().pick_folder() {
                    self.add_inputs(vec![p]);
                }
            }
            if !self.inputs.is_empty() && ui.button("Clear").clicked() {
                self.inputs.clear();
                self.input_bytes = 0;
            }
        });
        egui::ScrollArea::vertical().max_height(140.0).show(ui, |ui| {
            for p in &self.inputs {
                ui.label(p.display().to_string());
            }
        });
        ui.separator();
        ui.horizontal(|ui| {
            ui.label("Protection");
            ui.add(egui::Slider::new(&mut self.protect_pct, 0.0..=30.0).suffix("%"));
        });
        let tiny = self.input_bytes < (1 << 20);
        ui.label(RichText::new(if self.protect_pct == 0.0 {
            "No recovery data: damage can be detected but not repaired.".to_string()
        } else if tiny {
            "Small archive: it gets a minimum safety margin, which protects against a bad sector but not a dead drive. Keep a second copy elsewhere.".to_string()
        } else {
            format!("Targets {:.0}% recovery data relative to stored bytes.", self.protect_pct)
        }).color(MUTED));
        egui::ComboBox::from_label("Compression")
            .selected_text(["None (store)", "Fast (lz4)", "Normal (zstd 6)", "Max (zstd 19)"][self.compression])
            .show_ui(ui, |ui| {
                for (i, l) in ["None (store)", "Fast (lz4)", "Normal (zstd 6)", "Max (zstd 19)"].iter().enumerate() {
                    ui.selectable_value(&mut self.compression, i, *l);
                }
            });
        ui.checkbox(&mut self.encrypt, "Encrypt with a password");
        if self.encrypt {
            ui.add(egui::TextEdit::singleline(&mut self.password).password(true).hint_text("password"));
        }
        ui.add_space(8.0);
        let ready = self.busy.is_none() && !self.inputs.is_empty() && (!self.encrypt || !self.password.is_empty());
        if ui.add_enabled(ready, egui::Button::new("Create archive…")).clicked() {
            if let Some(out) = rfd::FileDialog::new().set_file_name("archive.rqz").save_file() {
                let inputs = self.inputs.clone();
                let mut opts = PackOptions::default();
                opts.compression =
                    [Compression::None, Compression::Fast, Compression::Normal, Compression::Max][self.compression];
                opts.protect = if self.protect_pct == 0.0 {
                    Protect::NONE
                } else {
                    Protect { ratio: self.protect_pct as f64 / 100.0, min_repair: 4 }
                };
                opts.password = self.encrypt.then(|| self.password.clone());
                let password = opts.password.clone();
                self.spawn(ctx, "Packing", move |p| match fsops::pack_paths(&inputs, &out, opts, true, p) {
                    Ok(r) => Msg::Finished {
                        text: format!(
                            "Created {} · {} files · verified after write ({} blocks, 0 errors).",
                            out.display(),
                            r.summary.files,
                            r.summary.blocks
                        ),
                        ok: true,
                        open: Some((out.clone(), password)),
                    },
                    Err(e) => Msg::Finished { text: e.to_string(), ok: false, open: None },
                });
            }
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll(ctx);
        // Drag and drop: an archive opens, anything else goes into a new archive.
        let dropped: Vec<PathBuf> = ctx.input(|i| i.raw.dropped_files.iter().filter_map(|f| f.path.clone()).collect());
        if !dropped.is_empty() && self.busy.is_none() {
            let is_rqz = |p: &PathBuf| {
                p.extension()
                    .map(|e| {
                        let e = e.to_string_lossy();
                        e == "rqz" || e == "rqzp" || (e.len() >= 3 && e.bytes().all(|c| c.is_ascii_digit()))
                    })
                    .unwrap_or(false)
            };
            if dropped.len() == 1 && is_rqz(&dropped[0]) {
                self.open(ctx, dropped[0].clone(), None);
            } else {
                self.add_inputs(dropped);
            }
        }

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("razerq").size(20.0).strong());
                ui.separator();
                if ui.button("Open archive…").clicked() && self.busy.is_none() {
                    self.pick_open(ctx);
                }
                ui.selectable_value(&mut self.tab, Tab::Files, "Files");
                ui.selectable_value(&mut self.tab, Tab::Health, "Health map");
                ui.selectable_value(&mut self.tab, Tab::New, "New archive");
            });
            ui.add_space(4.0);
        });

        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            if let Some((label, frac)) = &self.busy {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(label);
                    ui.add(egui::ProgressBar::new(*frac).desired_width(280.0));
                });
            } else if let Some((t, ok)) = &self.banner {
                ui.label(RichText::new(t).color(if *ok { GREEN } else { RED }));
            } else if let Some(o) = &self.opened {
                ui.label(RichText::new(o.path.display().to_string()).color(MUTED));
            } else {
                ui.label(RichText::new("Ready").color(MUTED));
            }
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            if self.opened.is_some() && self.tab != Tab::New {
                self.header_card(ui, ctx);
                ui.add_space(10.0);
            }
            match (self.tab, self.opened.is_some()) {
                (Tab::New, _) => self.new_tab(ui, ctx),
                (_, false) => {
                    ui.vertical_centered(|ui| {
                        ui.add_space(80.0);
                        ui.label(RichText::new("Drop an archive to check its health").size(22.0));
                        ui.label(RichText::new("or drop files and folders to pack them").color(MUTED));
                    });
                }
                (Tab::Files, true) => self.files_tab(ui),
                (Tab::Health, true) => self.health_tab(ui),
            }
        });

        // Password prompt for locked archives: health checks work without it, browsing needs it.
        if let Some(pw) = &mut self.unlock {
            let mut action = None;
            egui::Window::new("This archive is encrypted")
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .collapsible(false)
                .show(ctx, |ui| {
                    ui.label("Health checks and repair work without the password. Enter it to browse and extract.");
                    ui.add(egui::TextEdit::singleline(pw).password(true).hint_text("password"));
                    ui.horizontal(|ui| {
                        if ui.add_enabled(self.busy.is_none(), egui::Button::new("Unlock")).clicked() {
                            action = Some(true);
                        }
                        if ui.button("Not now").clicked() {
                            action = Some(false);
                        }
                    });
                });
            match action {
                Some(true) => {
                    let (pw, path) = (pw.clone(), self.opened.as_ref().map(|o| o.path.clone()));
                    self.unlock = None;
                    if let Some(p) = path {
                        self.open(ctx, p, Some(pw));
                    }
                }
                Some(false) => self.unlock = None,
                None => {}
            }
        }
    }
}

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([900.0, 640.0]).with_drag_and_drop(true),
        ..Default::default()
    };
    eframe::run_native("razerq", options, Box::new(|_cc| Ok(Box::new(App::new()))))
}
