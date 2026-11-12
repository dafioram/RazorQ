//! A read-only directory tree over an archive, shared by `mount` (FUSE) and `serve` (WebDAV).
//! Pure logic, no kernel or network: easy to test.

use crate::archive::Archive;
use crate::error::Result;
use crate::index::{FileEntry, KIND_DIR, KIND_SYMLINK};
use crate::storage::ReadAt;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeKind {
    Dir,
    File,
    Symlink,
}

#[derive(Clone, Debug)]
pub struct Node {
    pub name: String,
    pub parent: usize,
    pub kind: NodeKind,
    pub size: u64,
    pub mode: u32,
    pub mtime: i64,
    pub link: Option<String>,
    /// Children in name order (directories only).
    pub children: Vec<usize>,
    entry: Option<FileEntry>,
}

pub struct Vfs<S: ReadAt> {
    archive: Arc<Archive<S>>,
    nodes: Vec<Node>,
    names: HashMap<(usize, String), usize>,
}

impl<S: ReadAt> Vfs<S> {
    pub const ROOT: usize = 0;

    pub fn new(archive: Arc<Archive<S>>, snapshot: Option<u32>) -> Vfs<S> {
        let mut v = Vfs { archive: archive.clone(), nodes: Vec::new(), names: HashMap::new() };
        v.nodes.push(Node {
            name: String::new(),
            parent: 0,
            kind: NodeKind::Dir,
            size: 0,
            mode: 0o755,
            mtime: 0,
            link: None,
            children: vec![],
            entry: None,
        });
        for f in archive.visible_files(snapshot) {
            let comps: Vec<&str> = f.path.split('/').filter(|c| !c.is_empty() && *c != ".").collect();
            if comps.is_empty() || comps.contains(&"..") {
                continue;
            }
            let mut cur = Self::ROOT;
            for (i, c) in comps.iter().enumerate() {
                let last = i + 1 == comps.len();
                let existing = v.names.get(&(cur, c.to_string())).copied();
                let id = match existing {
                    Some(id) => id,
                    None => {
                        let id = v.nodes.len();
                        v.nodes.push(Node {
                            name: c.to_string(),
                            parent: cur,
                            kind: NodeKind::Dir,
                            size: 0,
                            mode: 0o755,
                            mtime: 0,
                            link: None,
                            children: vec![],
                            entry: None,
                        });
                        v.nodes[cur].children.push(id);
                        v.names.insert((cur, c.to_string()), id);
                        id
                    }
                };
                if last {
                    let n = &mut v.nodes[id];
                    n.mode = f.mode & 0o7777;
                    n.mtime = f.mtime;
                    match f.kind {
                        KIND_DIR => n.kind = NodeKind::Dir,
                        KIND_SYMLINK => {
                            n.kind = NodeKind::Symlink;
                            n.link = f.link.clone();
                            n.size = f.link.as_ref().map(|l| l.len() as u64).unwrap_or(0);
                        }
                        _ => {
                            n.kind = NodeKind::File;
                            n.size = f.size;
                            n.entry = Some(f.clone());
                        }
                    }
                }
                cur = id;
            }
        }
        for i in 0..v.nodes.len() {
            let mut kids = std::mem::take(&mut v.nodes[i].children);
            kids.sort_by(|a, b| v.nodes[*a].name.cmp(&v.nodes[*b].name));
            v.nodes[i].children = kids;
        }
        v
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.nodes.len() <= 1
    }
    pub fn node(&self, id: usize) -> Option<&Node> {
        self.nodes.get(id)
    }
    pub fn lookup(&self, parent: usize, name: &str) -> Option<usize> {
        self.names.get(&(parent, name.to_string())).copied()
    }
    /// Resolve a `/`-separated path (leading/trailing slashes and `.` ignored; `..` is refused).
    pub fn resolve(&self, path: &str) -> Option<usize> {
        let mut cur = Self::ROOT;
        for c in path.split('/').filter(|c| !c.is_empty() && *c != ".") {
            if c == ".." {
                return None;
            }
            cur = self.lookup(cur, c)?;
        }
        Some(cur)
    }
    pub fn path_of(&self, mut id: usize) -> String {
        let mut parts = Vec::new();
        while id != Self::ROOT {
            parts.push(self.nodes[id].name.clone());
            id = self.nodes[id].parent;
        }
        parts.reverse();
        parts.join("/")
    }
    /// Read bytes of a file node. Damage within the recovery budget is repaired in memory.
    pub fn read(&self, id: usize, offset: u64, len: usize) -> Result<Vec<u8>> {
        match self.nodes.get(id).and_then(|n| n.entry.as_ref()) {
            Some(e) => self.archive.read_range(e, offset, len),
            None => Ok(Vec::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::progress::Quiet;
    use crate::writer::{ArchiveWriter, PackOptions};
    use std::io::Cursor;

    #[test]
    fn tree_lookup_and_read() {
        let mut w = ArchiveWriter::create(Cursor::new(Vec::new()), PackOptions::default(), &Quiet).unwrap();
        w.add_dir("docs", 0o755, 5).unwrap();
        w.add_bytes("docs/a.txt", 0o644, 10, b"hello world").unwrap();
        w.add_bytes("docs/deep/er/b.txt", 0o600, 11, &vec![7u8; 5_000_000]).unwrap(); // implicit dirs, several blocks
        w.add_symlink("docs/link", "a.txt", 0o777, 0).unwrap();
        w.add_bytes("top.bin", 0o644, 0, b"x").unwrap();
        let a = Arc::new(Archive::open(w.finish().unwrap().0.into_inner(), None).unwrap());
        let v = Vfs::new(a, None);
        let docs = v.resolve("/docs/").unwrap();
        assert_eq!(v.node(docs).unwrap().kind, NodeKind::Dir);
        let names: Vec<_> = v.node(docs).unwrap().children.iter().map(|&c| v.node(c).unwrap().name.as_str()).collect();
        assert_eq!(names, vec!["a.txt", "deep", "link"]);
        let a_txt = v.resolve("docs/a.txt").unwrap();
        assert_eq!(v.read(a_txt, 6, 100).unwrap(), b"world");
        assert_eq!(v.read(a_txt, 50, 10).unwrap(), b"");
        let big = v.resolve("docs/deep/er/b.txt").unwrap();
        // a read that spans two blocks
        let chunk = v.read(big, 2_097_100, 300).unwrap();
        assert_eq!(chunk.len(), 300);
        assert!(chunk.iter().all(|&b| b == 7));
        assert_eq!(v.node(v.resolve("docs/link").unwrap()).unwrap().link.as_deref(), Some("a.txt"));
        assert_eq!(v.path_of(big), "docs/deep/er/b.txt");
        assert!(v.resolve("docs/../top.bin").is_none());
        assert!(v.resolve("nope").is_none());
    }
}
