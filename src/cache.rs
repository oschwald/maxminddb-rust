//! A reader-bound cache of complete deserialized records.

use std::net::IpAddr;

use ipnetwork::IpNetwork;
use serde::Deserialize;

use crate::{LookupResult, MaxMindDbError, Reader};

/// A two-entry cache for one reader and one decoded type.
///
/// Create one with [`Reader::record_cache()`]. Entries borrow from that reader
/// when `T` supports borrowed deserialization. The cache needs no `Clone`,
/// `Default`, or `'static` bound on `T`.
///
/// Frequently reused records receive up to three reuse credits. Record-cache
/// misses consume credits and halve them every 16 successful decodes so old
/// entries cannot stay protected forever. A miss may be decoded without
/// replacing a protected entry. IPs without a record do not affect this policy.
///
/// Memory includes space for two values of `T`, bookkeeping, and any allocations
/// owned by cached values. It is not a fixed byte limit. The cache needs mutable
/// access; create one per consumer while sharing the underlying reader.
#[derive(Debug)]
pub struct RecordCache<'data, S: AsRef<[u8]>, T> {
    reader: &'data Reader<S>,
    values: Box<[Option<T>; 2]>,
    keys: [Option<usize>; 2],
    credits: [u8; 2],
    next: usize,
    misses: u8,
}

impl<'data, S: AsRef<[u8]>, T: Deserialize<'data>> RecordCache<'data, S, T> {
    pub(crate) fn new(reader: &'data Reader<S>) -> Self {
        Self {
            reader,
            values: Box::new([None, None]),
            keys: [None, None],
            credits: [0, 0],
            next: 0,
            misses: 0,
        }
    }

    /// Look up an IP and reuse or decode its complete record.
    ///
    /// The result exposes data by reference, without cloning cached values.
    /// Its network and offset describe this lookup, even when another IP
    /// populated the cached record. It must be dropped before the next mutable
    /// access to this cache.
    ///
    /// Missing records and decoding errors are not cached. Failed decoding
    /// leaves the cache unchanged, so later lookups retry normally.
    #[inline(always)]
    pub fn lookup(
        &mut self,
        address: IpAddr,
    ) -> Result<CachedLookup<'_, 'data, S, T>, MaxMindDbError> {
        let lookup = self.reader.lookup(address)?;
        let Some(offset) = lookup.offset() else {
            return Ok(CachedLookup { lookup, data: None });
        };
        if let Some(slot) = self.keys.iter().position(|&key| key == Some(offset)) {
            self.credits[slot] = self.credits[slot].saturating_add(1).min(3);
            return Ok(CachedLookup {
                lookup,
                data: Some(CachedValue::Borrowed(self.values[slot].as_ref().unwrap())),
            });
        }

        // Publish a key only after decoding succeeds. An error must never make
        // an older cached value look like the result of this new offset.
        let value = lookup.decode::<T>()?.expect("a found lookup has a record");
        self.misses = self.misses.wrapping_add(1);
        if self.misses & 15 == 0 {
            for credit in &mut self.credits {
                *credit >>= 1;
            }
        }
        let slot = self
            .keys
            .iter()
            .position(Option::is_none)
            .unwrap_or_else(|| {
                let other = self.next ^ 1;
                if self.credits[other] < self.credits[self.next] {
                    other
                } else {
                    self.next
                }
            });
        let data = if self.credits[slot] > 0 {
            self.credits[slot] -= 1;
            CachedValue::Owned(value)
        } else {
            self.keys[slot] = Some(offset);
            self.values[slot] = Some(value);
            self.next = slot ^ 1;
            CachedValue::Borrowed(self.values[slot].as_ref().unwrap())
        };
        Ok(CachedLookup {
            lookup,
            data: Some(data),
        })
    }
}

#[derive(Debug)]
enum CachedValue<'cache, T> {
    Borrowed(&'cache T),
    Owned(T),
}

/// A lookup with an already decoded record, returned by [`RecordCache::lookup()`].
///
/// A result borrows a cached value or owns a value that was not admitted to the
/// cache. Both are accessed with [`data()`](Self::data), without a `Clone` bound.
/// Metadata always comes from the current IP lookup, not from the cached value.
#[derive(Debug)]
pub struct CachedLookup<'cache, 'data, S: AsRef<[u8]>, T> {
    lookup: LookupResult<'data, S>,
    data: Option<CachedValue<'cache, T>>,
}

impl<S: AsRef<[u8]>, T> CachedLookup<'_, '_, S, T> {
    /// Return the complete decoded record, or `None` when the IP has no data.
    #[inline]
    pub fn data(&self) -> Option<&T> {
        self.data.as_ref().map(|value| match value {
            CachedValue::Borrowed(value) => *value,
            CachedValue::Owned(value) => value,
        })
    }

    /// Return whether this IP has a successfully decoded record.
    #[inline]
    pub fn has_data(&self) -> bool {
        self.data.is_some()
    }

    /// Return the network containing the current IP address.
    pub fn network(&self) -> Result<IpNetwork, MaxMindDbError> {
        self.lookup.network()
    }

    /// Return this record's data-section offset, or `None` for a missing record.
    #[inline]
    pub fn offset(&self) -> Option<usize> {
        self.lookup.offset()
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::HashSet;

    use super::*;
    use crate::WithinOptions;
    use serde::de::Error as _;
    use serde_json::Value;

    thread_local! {
        static DECODES: Cell<usize> = const { Cell::new(0) };
        static FAIL_NEXT: Cell<bool> = const { Cell::new(false) };
    }

    // Intentionally neither Clone nor Default.
    #[derive(Debug)]
    struct Counted(Value);

    impl<'de> Deserialize<'de> for Counted {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            DECODES.with(|n| n.set(n.get() + 1));
            if FAIL_NEXT.with(|flag| flag.replace(false)) {
                return Err(D::Error::custom("test decoding failure"));
            }
            Value::deserialize(deserializer).map(Counted)
        }
    }

    fn reader() -> Reader<Vec<u8>> {
        Reader::open_readfile("test-data/test-data/GeoIP2-City-Test.mmdb").unwrap()
    }

    fn distinct_ips(reader: &Reader<Vec<u8>>) -> Vec<IpAddr> {
        let mut offsets = HashSet::new();
        reader
            .networks(WithinOptions::default())
            .unwrap()
            .map(Result::unwrap)
            .filter(|lookup| offsets.insert(lookup.offset().unwrap()))
            .take(4)
            .map(|lookup| lookup.network().unwrap().ip())
            .collect()
    }

    #[test]
    fn values_and_networks_match_uncached_lookups() {
        for bits in [24, 28, 32] {
            for family in ["ipv4", "ipv6", "mixed"] {
                let reader = Reader::open_readfile(format!(
                    "test-data/test-data/MaxMind-DB-test-{family}-{bits}.mmdb"
                ))
                .unwrap();
                let mut cache = reader.record_cache::<Value>();
                let options = WithinOptions::default()
                    .include_aliased_networks()
                    .include_networks_without_data();
                for lookup in reader.networks(options).unwrap() {
                    let network = lookup.unwrap().network().unwrap();
                    for ip in [network.network(), network.broadcast(), network.network()] {
                        let expected = reader.lookup(ip).unwrap();
                        let actual = cache.lookup(ip).unwrap();
                        assert_eq!(actual.data(), expected.decode::<Value>().unwrap().as_ref());
                        assert_eq!(actual.offset(), expected.offset());
                        assert_eq!(actual.has_data(), expected.has_data());
                        assert_eq!(actual.network().unwrap(), expected.network().unwrap());
                    }
                }
            }
        }
    }

    #[test]
    fn same_record_is_decoded_once_for_different_ips() {
        let reader = reader();
        let mut cache = reader.record_cache::<Counted>();
        let a: IpAddr = "89.160.20.128".parse().unwrap();
        let b: IpAddr = "89.160.20.129".parse().unwrap();
        assert_eq!(
            reader.lookup(a).unwrap().offset(),
            reader.lookup(b).unwrap().offset()
        );
        DECODES.with(|n| n.set(0));
        for ip in [a, b, a, b] {
            let cached = cache.lookup(ip).unwrap();
            assert_eq!(
                &cached.data().unwrap().0,
                &reader
                    .lookup(ip)
                    .unwrap()
                    .decode::<Value>()
                    .unwrap()
                    .unwrap()
            );
            assert_eq!(
                cached.network().unwrap(),
                reader.lookup(ip).unwrap().network().unwrap()
            );
        }
        assert_eq!(DECODES.with(Cell::get), 1);
    }

    #[test]
    fn failed_decodes_do_not_replace_or_poison_cached_values() {
        let reader = reader();
        let ips = distinct_ips(&reader);
        assert_eq!(ips.len(), 4);
        let mut cache = reader.record_cache::<Counted>();
        for _ in 0..4 {
            cache.lookup(ips[0]).unwrap();
            cache.lookup(ips[1]).unwrap();
        }
        FAIL_NEXT.with(|flag| flag.set(true));
        let error = cache.lookup(ips[2]).unwrap_err();
        assert!(error.to_string().contains("test decoding failure"));
        let before = DECODES.with(Cell::get);
        for &ip in &ips[..2] {
            let result = cache.lookup(ip).unwrap();
            assert_eq!(
                &result.data().unwrap().0,
                &reader
                    .lookup(ip)
                    .unwrap()
                    .decode::<Value>()
                    .unwrap()
                    .unwrap()
            );
        }
        assert_eq!(DECODES.with(Cell::get), before);
        // The new record is decoded successfully on retry, even if it bypasses
        // the protected entries. Dropping the result drops that temporary value.
        for _ in 0..2 {
            let result = cache.lookup(ips[2]).unwrap();
            assert_eq!(
                &result.data().unwrap().0,
                &reader
                    .lookup(ips[2])
                    .unwrap()
                    .decode::<Value>()
                    .unwrap()
                    .unwrap()
            );
        }
        assert_eq!(DECODES.with(Cell::get), before + 2);
    }

    #[test]
    fn cache_adapts_to_a_new_working_set() {
        let reader = reader();
        let ips = distinct_ips(&reader);
        assert_eq!(ips.len(), 4);
        let mut cache = reader.record_cache::<Counted>();
        for _ in 0..64 {
            cache.lookup(ips[0]).unwrap();
            cache.lookup(ips[1]).unwrap();
        }
        for _ in 0..128 {
            cache.lookup(ips[2]).unwrap();
            cache.lookup(ips[3]).unwrap();
        }
        let before = DECODES.with(Cell::get);
        for _ in 0..64 {
            cache.lookup(ips[2]).unwrap();
            cache.lookup(ips[3]).unwrap();
        }
        assert_eq!(
            DECODES.with(Cell::get),
            before,
            "new hot records must replace stale ones"
        );
    }

    #[test]
    fn missing_records_do_not_decode() {
        let reader = reader();
        let mut cache = reader.record_cache::<Counted>();
        let before = DECODES.with(Cell::get);
        let ip = "192.0.2.1".parse().unwrap();
        assert!(!reader.lookup(ip).unwrap().has_data());
        for _ in 0..2 {
            let result = cache.lookup(ip).unwrap();
            assert!(result.data().is_none());
            assert!(!result.has_data());
            assert!(result.offset().is_none());
            assert_eq!(
                result.network().unwrap(),
                reader.lookup(ip).unwrap().network().unwrap()
            );
        }
        assert_eq!(DECODES.with(Cell::get), before);
    }

    #[test]
    fn borrowed_records_and_shared_readers_are_supported() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Reader<Vec<u8>>>();
        let reader = reader();
        let mut first = reader.record_cache::<crate::geoip2::City>();
        let mut second = reader.record_cache::<crate::geoip2::Country>();
        let ip = "89.160.20.128".parse().unwrap();
        let city = first.lookup(ip).unwrap();
        let country = second.lookup(ip).unwrap();
        assert_eq!(city.data().unwrap().country.iso_code, Some("SE"));
        assert_eq!(
            city.data().unwrap().country.iso_code,
            country.data().unwrap().country.iso_code
        );
    }
}
