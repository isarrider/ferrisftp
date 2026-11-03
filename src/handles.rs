//! Open file and directory handles.
//!
//! Handles go over the wire as opaque 4-byte strings. Ids are never reused
//! while a handle with the same id is open, and the table is capped so a
//! client cannot exhaust file descriptors.

use std::collections::HashMap;
use std::fs::{File, ReadDir};
use std::path::PathBuf;

use crate::protocol::MAX_HANDLES;

pub enum Handle {
    File {
        file: File,
    },
    Dir {
        path: PathBuf,
        entries: ReadDir,
        /// "." and ".." have been returned already.
        dots_sent: bool,
    },
}

#[derive(Default)]
pub struct HandleTable {
    open: HashMap<u32, Handle>,
    next_id: u32,
}

/// The table is full.
#[derive(Debug)]
pub struct TooManyHandles;

impl HandleTable {
    pub fn insert(&mut self, handle: Handle) -> Result<[u8; 4], TooManyHandles> {
        if self.open.len() >= MAX_HANDLES {
            return Err(TooManyHandles);
        }
        // With at most MAX_HANDLES ids in use this finds a free one quickly.
        while self.open.contains_key(&self.next_id) {
            self.next_id = self.next_id.wrapping_add(1);
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.open.insert(id, handle);
        Ok(id.to_be_bytes())
    }

    fn decode(raw: &[u8]) -> Option<u32> {
        let bytes: [u8; 4] = raw.try_into().ok()?;
        Some(u32::from_be_bytes(bytes))
    }

    pub fn get_mut(&mut self, raw: &[u8]) -> Option<&mut Handle> {
        self.open.get_mut(&Self::decode(raw)?)
    }

    pub fn remove(&mut self, raw: &[u8]) -> Option<Handle> {
        self.open.remove(&Self::decode(raw)?)
    }

    pub fn len(&self) -> usize {
        self.open.len()
    }

    pub fn is_empty(&self) -> bool {
        self.open.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_handle() -> Handle {
        Handle::File {
            file: File::open("/dev/null").unwrap(),
        }
    }

    #[test]
    fn insert_get_remove() {
        let mut t = HandleTable::default();
        let a = t.insert(file_handle()).unwrap();
        let b = t.insert(file_handle()).unwrap();
        assert_ne!(a, b);
        assert!(t.get_mut(&a).is_some());
        assert!(t.remove(&a).is_some());
        assert!(t.get_mut(&a).is_none());
        assert!(t.get_mut(b"bogus").is_none());
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn capped() {
        let mut t = HandleTable::default();
        for _ in 0..MAX_HANDLES {
            t.insert(file_handle()).unwrap();
        }
        assert!(t.insert(file_handle()).is_err());
    }
}
