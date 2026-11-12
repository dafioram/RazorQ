//! `rqz serve`: a read-only WebDAV server, so an archive can be mapped as a drive on Windows
//! (Map network drive / `net use`), macOS (Finder, Connect to Server) and Linux (davfs2, GVfs),
//! without any kernel driver. Also browsable in a web browser.

use anyhow::{Context, Result};
use rqz_core::archive::Archive;
use rqz_core::fsops::Source;
use rqz_core::vfs::{NodeKind, Vfs};
use std::io::Read;
use std::sync::Arc;
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

const CHUNK: usize = 1 << 20;

fn header(k: &str, v: &str) -> Header {
    Header::from_bytes(k.as_bytes(), v.as_bytes()).unwrap()
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn percent_encode_path(p: &str) -> String {
    let mut o = String::new();
    for c in p.bytes() {
        match c {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => o.push(c as char),
            _ => o.push_str(&format!("%{c:02X}")),
        }
    }
    o
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// Days since 1970-01-01 -> (year, month, day).
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn http_date(t: i64) -> String {
    let t = t.max(0);
    let (days, rem) = (t / 86400, t % 86400);
    let (y, m, d) = civil(days);
    let wd = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"][(days % 7) as usize];
    let mon = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][(m - 1) as usize];
    format!("{wd}, {d:02} {mon} {y} {:02}:{:02}:{:02} GMT", rem / 3600, rem % 3600 / 60, rem % 60)
}

fn iso_date(t: i64) -> String {
    let t = t.max(0);
    let (y, m, d) = civil(t / 86400);
    let rem = t % 86400;
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

fn content_type(name: &str) -> &'static str {
    match name.rsplit('.').next().unwrap_or("").to_ascii_lowercase().as_str() {
        "txt" | "md" | "log" | "csv" => "text/plain; charset=utf-8",
        "html" | "htm" => "text/html; charset=utf-8",
        "json" => "application/json",
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "pdf" => "application/pdf",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "zip" => "application/zip",
        _ => "application/octet-stream",
    }
}

/// Streams a file range lazily, so huge files never sit in memory.
struct RangeReader {
    vfs: Arc<Vfs<Source>>,
    id: usize,
    pos: u64,
    end: u64,
}

impl Read for RangeReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.end || buf.is_empty() {
            return Ok(0);
        }
        let want = buf.len().min(CHUNK).min((self.end - self.pos) as usize);
        let data = self.vfs.read(self.id, self.pos, want).map_err(|e| std::io::Error::other(e.to_string()))?;
        if data.is_empty() {
            return Ok(0);
        }
        buf[..data.len()].copy_from_slice(&data);
        self.pos += data.len() as u64;
        Ok(data.len())
    }
}

fn parse_range(h: &str, size: u64) -> Option<(u64, u64)> {
    let spec = h.strip_prefix("bytes=")?;
    let (a, b) = spec.split_once('-')?;
    if size == 0 {
        return None;
    }
    if a.is_empty() {
        let n: u64 = b.parse().ok()?;
        return Some((size.saturating_sub(n), size - 1));
    }
    let start: u64 = a.parse().ok()?;
    let end: u64 = if b.is_empty() { size - 1 } else { b.parse::<u64>().ok()?.min(size - 1) };
    (start <= end && start < size).then_some((start, end))
}

fn respond(req: Request, status: u16, headers: Vec<Header>, body: Vec<u8>) {
    let mut r = Response::from_data(body).with_status_code(StatusCode(status));
    for h in headers {
        r.add_header(h);
    }
    let _ = req.respond(r);
}

fn propfind_entry(href: &str, name: &str, kind: NodeKind, size: u64, mtime: i64) -> String {
    let is_dir = kind == NodeKind::Dir;
    let mut href = percent_encode_path(href);
    if is_dir && !href.ends_with('/') {
        href.push('/');
    }
    format!(
        "<D:response><D:href>{href}</D:href><D:propstat><D:prop><D:displayname>{}</D:displayname>\
         <D:resourcetype>{}</D:resourcetype>{}<D:getlastmodified>{}</D:getlastmodified>\
         <D:creationdate>{}</D:creationdate></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>",
        xml_escape(name),
        if is_dir { "<D:collection/>" } else { "" },
        if is_dir {
            String::new()
        } else {
            format!(
                "<D:getcontentlength>{size}</D:getcontentlength><D:getcontenttype>{}</D:getcontenttype>",
                content_type(name)
            )
        },
        http_date(mtime),
        iso_date(mtime)
    )
}

fn handle(vfs: &Arc<Vfs<Source>>, req: Request) {
    let method = req.method().clone();
    let raw = req.url().split('?').next().unwrap_or("/").to_string();
    let path = percent_decode(&raw);
    let dav = vec![header("DAV", "1"), header("MS-Author-Via", "DAV"), header("Accept-Ranges", "bytes")];

    if method == Method::Options {
        let mut h = dav;
        h.push(header("Allow", "OPTIONS, GET, HEAD, PROPFIND"));
        return respond(req, 200, h, vec![]);
    }
    let read_method = matches!(method, Method::Get | Method::Head) || method.as_str() == "PROPFIND";
    if !read_method {
        let mut h = dav;
        h.push(header("Allow", "OPTIONS, GET, HEAD, PROPFIND"));
        return respond(req, 405, h, b"this drive is read-only".to_vec());
    }
    let Some(id) = vfs.resolve(&path) else {
        return respond(req, 404, vec![], b"not found".to_vec());
    };
    let node = vfs.node(id).unwrap().clone();

    match method {
        Method::Head | Method::Get if node.kind == NodeKind::Dir => {
            let mut html = format!(
                "<!doctype html><meta charset=utf-8><title>/{}</title><h1>/{}</h1><ul>",
                xml_escape(path.trim_matches('/')),
                xml_escape(path.trim_matches('/'))
            );
            for &c in &node.children {
                let cn = vfs.node(c).unwrap();
                let slash = if cn.kind == NodeKind::Dir { "/" } else { "" };
                html.push_str(&format!(
                    "<li><a href=\"{}{slash}\">{}{slash}</a>",
                    percent_encode_path(&format!("/{}", vfs.path_of(c))),
                    xml_escape(&cn.name)
                ));
            }
            let body = if method == Method::Head { vec![] } else { html.into_bytes() };
            respond(req, 200, vec![header("Content-Type", "text/html; charset=utf-8")], body)
        }
        Method::Head | Method::Get => {
            let size = node.size;
            let range =
                req.headers().iter().find(|h| h.field.equiv("Range")).and_then(|h| parse_range(h.value.as_str(), size));
            let (status, start, end) = match range {
                Some((a, b)) => (206u16, a, b + 1),
                None => (200u16, 0, size),
            };
            let mut r: Response<Box<dyn Read + Send>> = if method == Method::Head {
                // tiny_http sends the headers (with the right Content-Length) and no body for HEAD.
                Response::new(
                    StatusCode(status),
                    vec![],
                    Box::new(std::io::empty()),
                    Some((end - start) as usize),
                    None,
                )
            } else if start >= end {
                Response::new(StatusCode(status), vec![], Box::new(std::io::empty()), Some(0), None)
            } else {
                let rd = RangeReader { vfs: vfs.clone(), id, pos: start, end };
                Response::new(StatusCode(status), vec![], Box::new(rd), Some((end - start) as usize), None)
            };
            r.add_header(header("Content-Type", content_type(&node.name)));
            r.add_header(header("Accept-Ranges", "bytes"));
            r.add_header(header("Last-Modified", &http_date(node.mtime)));
            if status == 206 {
                r.add_header(header("Content-Range", &format!("bytes {start}-{}/{size}", end - 1)));
            }
            let _ = req.respond(r);
        }
        m if m.as_str() == "PROPFIND" => {
            let depth = req.headers().iter().find(|h| h.field.equiv("Depth")).map(|h| h.value.as_str().to_string());
            let base = format!("/{}", vfs.path_of(id));
            let mut xml = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?><D:multistatus xmlns:D=\"DAV:\">");
            xml.push_str(&propfind_entry(&base, &node.name, node.kind, node.size, node.mtime));
            if node.kind == NodeKind::Dir && depth.as_deref() != Some("0") {
                for &c in &node.children {
                    let cn = vfs.node(c).unwrap();
                    xml.push_str(&propfind_entry(
                        &format!("/{}", vfs.path_of(c)),
                        &cn.name,
                        cn.kind,
                        cn.size,
                        cn.mtime,
                    ));
                }
            }
            xml.push_str("</D:multistatus>");
            let mut h = dav;
            h.push(header("Content-Type", "application/xml; charset=utf-8"));
            respond(req, 207, h, xml.into_bytes())
        }
        _ => {
            let mut h = dav;
            h.push(header("Allow", "OPTIONS, GET, HEAD, PROPFIND"));
            respond(req, 405, h, b"this drive is read-only".to_vec())
        }
    }
}

pub fn run(a: Arc<Archive<Source>>, bind: &str, port: u16, snapshot: Option<u32>) -> Result<()> {
    let vfs = Arc::new(Vfs::new(a, snapshot));
    let addr = format!("{bind}:{port}");
    let server = Arc::new(Server::http(&addr).map_err(|e| anyhow::anyhow!("cannot listen on {addr}: {e}"))?);
    if bind != "127.0.0.1" && bind != "localhost" {
        eprintln!("  ⚠ listening on {bind}: anyone who can reach this address can read the archive (no password)");
    }
    eprintln!("  serving read-only at http://{addr}/   (Ctrl+C to stop)");
    eprintln!("  Windows:  net use Z: http://{addr}/");
    eprintln!("  macOS:    Finder → Go → Connect to Server → http://{addr}/");
    eprintln!("  Linux:    mount -t davfs http://{addr}/ /mnt/rqz   (or open it in a file manager)");
    let mut workers = Vec::new();
    for _ in 0..4 {
        let (server, vfs) = (server.clone(), vfs.clone());
        workers.push(std::thread::spawn(move || {
            for req in server.incoming_requests() {
                handle(&vfs, req);
            }
        }));
    }
    for w in workers {
        w.join().map_err(|_| anyhow::anyhow!("server thread panicked")).context("serve")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(http_date(1_700_000_000), "Tue, 14 Nov 2023 22:13:20 GMT");
        assert_eq!(iso_date(1_700_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn ranges_and_escaping() {
        assert_eq!(parse_range("bytes=0-9", 100), Some((0, 9)));
        assert_eq!(parse_range("bytes=90-", 100), Some((90, 99)));
        assert_eq!(parse_range("bytes=-10", 100), Some((90, 99)));
        assert_eq!(parse_range("bytes=200-300", 100), None);
        assert_eq!(percent_decode("a%20b%2Fc"), "a b/c");
        assert_eq!(percent_encode_path("/my dir/é.txt"), "/my%20dir/%C3%A9.txt");
    }
}
