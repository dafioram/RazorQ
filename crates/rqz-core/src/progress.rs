//! A tiny event stream shared by the CLI (progress bars / NDJSON) and the GUI.

#[derive(Clone, Debug)]
pub enum Event {
    Stage(String),
    Progress { done: u64, total: u64 },
    Note(String),
}

pub trait Progress: Sync {
    fn emit(&self, event: Event);
}

pub struct Quiet;
impl Progress for Quiet {
    fn emit(&self, _event: Event) {}
}

impl<F: Fn(Event) + Sync> Progress for F {
    fn emit(&self, event: Event) {
        self(event)
    }
}
