// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2023 Oxide Computer Company

//! Cache of interface names to indices and vice versa.

use fxhash::FxHashMap;
use nix::libc::c_uint;
use nix::net::if_::if_nameindex;
use nix::net::if_::if_nametoindex;
use std::fmt;
use std::ops::Deref;
use string_cache::DefaultAtom;
use thiserror::Error;
use tokio::sync::Mutex;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum InterfaceError {
    #[error("if_nametoindex({name:?}) failed: {err}")]
    IfNameToIndex { name: String, err: nix::Error },
    #[error("if_nameindex() failed: {0}")]
    IfNameIndex(nix::Error),
    #[error("non-UTF8 interface: {0:?}")]
    NonUtf8Interface(Vec<u8>),
    #[error("no interface name found for index {0}")]
    NoNameFound(u32),
}

type Result<T> = std::result::Result<T, InterfaceError>;

// These type aliases and the existence of `Inner` below allow us to unit test
// this function without actually calling `if_nameindex()` or
// `if_indextoname()` via dependency injection. In the real `ScopeIdCache` we
// perform lookups using nix's wrappers of those functions; in unit tests, we
// give `Inner` closures to perform lookups into a test harness we create.
type StaticNameToIndex = fn(&str) -> Result<c_uint>;
type StaticIndexToName = fn(c_uint) -> Result<String>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Name(DefaultAtom);

impl Deref for Name {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<&'_ str> for Name {
    fn from(s: &'_ str) -> Self {
        Self(DefaultAtom::from(s))
    }
}

#[derive(Debug)]
pub(crate) struct ScopeIdCache {
    inner: Inner<StaticNameToIndex, StaticIndexToName>,
}

impl Default for ScopeIdCache {
    fn default() -> Self {
        Self {
            inner: Inner {
                sys_name_to_index: nix_name_to_index,
                sys_index_to_name: nix_index_to_name,
                map: Mutex::default(),
            },
        }
    }
}

impl ScopeIdCache {
    pub(crate) async fn index_to_name(&self, index: u32) -> Result<Name> {
        self.inner.index_to_name(index).await
    }

    pub(crate) async fn refresh_by_name(&self, name: &str) -> Result<u32> {
        self.inner.refresh_by_name(name).await
    }
}

struct Inner<F, G> {
    sys_name_to_index: F,
    sys_index_to_name: G,
    map: Mutex<BidirMap>,
}

impl<F, G> fmt::Debug for Inner<F, G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Inner").field("map", &self.map).finish()
    }
}

#[derive(Debug, Default)]
struct BidirMap {
    index_to_name: FxHashMap<u32, DefaultAtom>,
    name_to_index: FxHashMap<DefaultAtom, u32>,
}

impl<F, G> Inner<F, G>
where
    F: Fn(&str) -> Result<c_uint> + Clone + Send + 'static,
    G: Fn(c_uint) -> Result<String> + Clone + Send + 'static,
{
    async fn refresh_by_name(&self, name: &str) -> Result<u32> {
        let name = DefaultAtom::from(name);
        let mut map = self.map.lock().await;

        // Remove previous entries (if any).
        if let Some(index) = map.name_to_index.remove(&name) {
            map.index_to_name.remove(&index);
        }

        // Look up current index.
        self.perform_name_to_index_lookup(name, map).await
    }

    async fn index_to_name(&self, index: u32) -> Result<Name> {
        let mut map = self.map.lock().await;

        // Do we have this index cached already?
        if let Some(name) = map.index_to_name.get(&index).cloned() {
            return Ok(Name(name));
        }

        // Not cached - call `if_indextoname()` to find it.
        let sys_index_to_name = self.sys_index_to_name.clone();
        let name =
            tokio::task::spawn_blocking(move || (sys_index_to_name)(index))
                .await
                .unwrap()?;

        // Intern the string for caching.
        let name = DefaultAtom::from(name.as_str());

        // Insert the lookup results for both directions. If this name was
        // previously cached to a different index, remove that entry. (We know
        // there's no entry for `index_to_name` because we checked above and
        // still hold the lock on `map`).
        if let Some(old) = map.name_to_index.insert(name.clone(), index) {
            map.index_to_name.remove(&old);
        }
        map.index_to_name.insert(index, name.clone());

        Ok(Name(name))
    }

    // We currently only use this function in unit tests. If we ever need this
    // in real code, remove this cfg and add a wrapper in `ScopeIdCache`.
    #[cfg(test)]
    async fn name_to_index(&self, name: &str) -> Result<u32> {
        // Intern `name` for cache lookup.
        let name = DefaultAtom::from(name);

        let map = self.map.lock().await;

        // Do we have this name cached already?
        if let Some(index) = map.name_to_index.get(&name).cloned() {
            return Ok(index);
        }

        // Not cached - call `if_nameindex()` to find it.
        self.perform_name_to_index_lookup(name, map).await
    }

    async fn perform_name_to_index_lookup(
        &self,
        name: DefaultAtom,
        mut map: tokio::sync::MutexGuard<'_, BidirMap>,
    ) -> Result<u32> {
        let sys_name_to_index = self.sys_name_to_index.clone();
        let index = {
            let name = name.clone();
            tokio::task::spawn_blocking(move || (sys_name_to_index)(&name))
                .await
                .unwrap()?
        };

        // Insert the lookup results for both directions. If this index was
        // previously cached to a different interface, remove that entry. (We
        // know there's no entry for `name_to_index` because we checked above
        // and still hold the lock on `map`.)
        if let Some(old) = map.index_to_name.insert(index, name.clone()) {
            map.name_to_index.remove(&old);
        }
        map.name_to_index.insert(name, index);

        Ok(index)
    }
}

fn nix_name_to_index(name: &str) -> Result<c_uint> {
    if_nametoindex(name).map_err(|err| InterfaceError::IfNameToIndex {
        name: name.to_string(),
        err,
    })
}

fn nix_index_to_name(index: c_uint) -> Result<String> {
    let pairs = if_nameindex().map_err(InterfaceError::IfNameIndex)?;
    for pair in &pairs {
        if pair.index() == index {
            let name = pair.name().to_str().map_err(|_| {
                InterfaceError::NonUtf8Interface(
                    pair.name().to_bytes().to_vec(),
                )
            })?;
            return Ok(name.to_string());
        }
    }

    Err(InterfaceError::NoNameFound(index))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    #[derive(Default)]
    struct Harness {
        name_to_index: Arc<std::sync::Mutex<FxHashMap<String, Result<u32>>>>,
        index_to_name: Arc<std::sync::Mutex<FxHashMap<u32, Result<String>>>>,
        name_to_index_calls: Arc<AtomicU64>,
        index_to_name_calls: Arc<AtomicU64>,
    }

    impl Harness {
        fn insert_ok(&self, name: &str, index: u32) {
            self.name_to_index
                .lock()
                .unwrap()
                .insert(name.to_string(), Ok(index));
            self.index_to_name
                .lock()
                .unwrap()
                .insert(index, Ok(name.to_string()));
        }

        fn insert_name_err(&self, name: &str, err: InterfaceError) {
            self.name_to_index
                .lock()
                .unwrap()
                .insert(name.to_string(), Err(err));
        }

        fn insert_index_err(&self, index: u32, err: InterfaceError) {
            self.index_to_name.lock().unwrap().insert(index, Err(err));
        }

        fn clear_map(&self) {
            self.name_to_index.lock().unwrap().clear();
            self.index_to_name.lock().unwrap().clear();
        }
    }

    macro_rules! inner_for_harness {
        ($harness: ident) => {{
            let sys_name_to_index = {
                let name_to_index = Arc::clone(&$harness.name_to_index);
                let name_to_index_calls =
                    Arc::clone(&$harness.name_to_index_calls);
                move |name: &str| {
                    name_to_index_calls.fetch_add(1, Ordering::SeqCst);
                    let name_to_index = name_to_index.lock().unwrap();
                    if let Some(result) = name_to_index.get(name).cloned() {
                        result
                    } else {
                        panic!("no harness result for name {name:?}");
                    }
                }
            };

            let sys_index_to_name = {
                let index_to_name = Arc::clone(&$harness.index_to_name);
                let index_to_name_calls =
                    Arc::clone(&$harness.index_to_name_calls);
                move |index| {
                    index_to_name_calls.fetch_add(1, Ordering::SeqCst);
                    let index_to_name = index_to_name.lock().unwrap();
                    if let Some(result) = index_to_name.get(&index).cloned() {
                        result
                    } else {
                        panic!("no harness result for index {index}");
                    }
                }
            };

            Inner {
                sys_name_to_index,
                sys_index_to_name,
                map: Mutex::default(),
            }
        }};
    }

    #[tokio::test]
    async fn basic_usage() {
        let harness = Harness::default();
        let inner = inner_for_harness!(harness);

        // Insert dummy interfaces that `Inner` thinks are coming from the
        // system.
        harness.insert_ok("A", 1);
        harness.insert_ok("B", 2);

        // Look up interface 1.
        assert_eq!(&*inner.index_to_name(1).await.unwrap(), "A");
        assert_eq!(harness.index_to_name_calls.load(Ordering::SeqCst), 1);
        assert_eq!(harness.name_to_index_calls.load(Ordering::SeqCst), 0);

        // Additional requests for either A or 1 should returned a cached result
        // and not trigger additional system calls.
        assert_eq!(&*inner.index_to_name(1).await.unwrap(), "A");
        assert_eq!(inner.name_to_index("A").await.unwrap(), 1);
        assert_eq!(harness.index_to_name_calls.load(Ordering::SeqCst), 1);
        assert_eq!(harness.name_to_index_calls.load(Ordering::SeqCst), 0);

        // Similarly, looking up interface "B" should result in 1 call to the
        // underlying name -> index system function...
        assert_eq!(inner.name_to_index("B").await.unwrap(), 2);
        assert_eq!(harness.index_to_name_calls.load(Ordering::SeqCst), 1);
        assert_eq!(harness.name_to_index_calls.load(Ordering::SeqCst), 1);

        // ...and future requests return cached results with no additional
        // system calls.
        assert_eq!(&*inner.index_to_name(1).await.unwrap(), "A");
        assert_eq!(&*inner.index_to_name(2).await.unwrap(), "B");
        assert_eq!(inner.name_to_index("A").await.unwrap(), 1);
        assert_eq!(inner.name_to_index("B").await.unwrap(), 2);
        assert_eq!(harness.index_to_name_calls.load(Ordering::SeqCst), 1);
        assert_eq!(harness.name_to_index_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn index_reuse_evicts_old_name() {
        let harness = Harness::default();
        let inner = inner_for_harness!(harness);

        // Prime `Inner` with "A" -> 1.
        harness.insert_ok("A", 1);
        assert_eq!(&*inner.index_to_name(1).await.unwrap(), "A");
        assert_eq!(inner.name_to_index("A").await.unwrap(), 1);
        assert_eq!(harness.index_to_name_calls.load(Ordering::SeqCst), 1);
        assert_eq!(harness.name_to_index_calls.load(Ordering::SeqCst), 0);

        // Pretend the system has reused index 1 for interface "B", and record a
        // dummy error for lookups of "A".
        harness.clear_map();
        harness.insert_ok("B", 1);
        harness.insert_name_err(
            "A",
            InterfaceError::IfNameIndex(nix::Error::ENXIO),
        );

        // When we look up B, we should get 1...
        assert_eq!(inner.name_to_index("B").await.unwrap(), 1);
        assert_eq!(&*inner.index_to_name(1).await.unwrap(), "B");
        assert_eq!(harness.index_to_name_calls.load(Ordering::SeqCst), 1);
        assert_eq!(harness.name_to_index_calls.load(Ordering::SeqCst), 1);

        // ... and we should get our dummy error if we try to look up A, because
        // it should no longer be cached and `inner` should call into our
        // harness again to try to look it up.
        assert_eq!(
            inner.name_to_index("A").await.unwrap_err(),
            InterfaceError::IfNameIndex(nix::Error::ENXIO)
        );
        assert_eq!(harness.index_to_name_calls.load(Ordering::SeqCst), 1);
        assert_eq!(harness.name_to_index_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn index_change_evicts_old_index() {
        let harness = Harness::default();
        let inner = inner_for_harness!(harness);

        // Prime `Inner` with "A" -> 1.
        harness.insert_ok("A", 1);
        assert_eq!(&*inner.index_to_name(1).await.unwrap(), "A");
        assert_eq!(inner.name_to_index("A").await.unwrap(), 1);
        assert_eq!(harness.index_to_name_calls.load(Ordering::SeqCst), 1);
        assert_eq!(harness.name_to_index_calls.load(Ordering::SeqCst), 0);

        // Pretend the system has changed A's interface to 2, which we will
        // discover by looking up the interface for index 2. Insert a dummy
        // error for index 1.
        harness.clear_map();
        harness.insert_ok("A", 2);
        harness.insert_index_err(
            1,
            InterfaceError::IfNameIndex(nix::Error::ENXIO),
        );

        // When we look up 2, we should get "A"...
        assert_eq!(&*inner.index_to_name(2).await.unwrap(), "A");
        assert_eq!(inner.name_to_index("A").await.unwrap(), 2);
        assert_eq!(harness.index_to_name_calls.load(Ordering::SeqCst), 2);
        assert_eq!(harness.name_to_index_calls.load(Ordering::SeqCst), 0);

        // ... and we should get our dummy error if we try to look up 1, because
        // it should no longer be cached and `inner` should call into our
        // harness again to try to look it up.
        assert_eq!(
            inner.index_to_name(1).await.unwrap_err(),
            InterfaceError::IfNameIndex(nix::Error::ENXIO)
        );
        assert_eq!(harness.index_to_name_calls.load(Ordering::SeqCst), 3);
        assert_eq!(harness.name_to_index_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn refresh_removes_both_directions() {
        let harness = Harness::default();
        let inner = inner_for_harness!(harness);

        harness.insert_ok("A", 1);

        // Lookup index 1; we should find it, and have 1 entry in each of
        // `inner.map`'s hashmaps.
        assert_eq!(&*inner.index_to_name(1).await.unwrap(), "A");
        assert_eq!(inner.name_to_index("A").await.unwrap(), 1);
        assert_eq!(harness.index_to_name_calls.load(Ordering::SeqCst), 1);
        assert_eq!(harness.name_to_index_calls.load(Ordering::SeqCst), 0);
        assert_eq!(inner.map.lock().await.index_to_name.len(), 1);
        assert_eq!(inner.map.lock().await.name_to_index.len(), 1);

        // Change A's index from 1 to 2, and refresh.
        harness.clear_map();
        harness.insert_ok("A", 2);

        assert_eq!(inner.refresh_by_name("A").await.unwrap(), 2);
        assert_eq!(&*inner.index_to_name(2).await.unwrap(), "A");
        assert_eq!(harness.index_to_name_calls.load(Ordering::SeqCst), 1);
        assert_eq!(harness.name_to_index_calls.load(Ordering::SeqCst), 1);

        // There should no longer be an entry for index 1, which will trigger a
        // lookup into `harness`; insert a dummy error we can check for.
        harness.insert_index_err(
            1,
            InterfaceError::IfNameIndex(nix::Error::ENXIO),
        );
        assert_eq!(
            inner.index_to_name(1).await.unwrap_err(),
            InterfaceError::IfNameIndex(nix::Error::ENXIO)
        );
        assert_eq!(inner.map.lock().await.index_to_name.len(), 1);
        assert_eq!(inner.map.lock().await.name_to_index.len(), 1);
    }
}
