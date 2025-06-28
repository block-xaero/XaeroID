use std::time::SystemTime;

use crate::XaeroID;

pub fn xaero_id_hash(id: &XaeroID) -> [u8; 32] {
    let bytes = bytemuck::bytes_of(id);
    *blake3::hash(bytes).as_bytes()
}

pub trait XaeroIdStorage {
    fn flush(&mut self, hash: [u8; 32], id: &XaeroID);
}
#[repr(C, align(64))]
pub struct XaeroIdHotCache<const N: usize> {
    count: usize,
    next_eviction: usize,
    entries: [([u8; 32], XaeroID, u64); N],
}
impl<const N: usize> XaeroIdHotCache<N> {
    pub const fn new() -> Self {
        // Compile-time check
        Self {
            count: 0,
            next_eviction: 0,
            entries: unsafe { std::mem::zeroed() }, // Safe for POD types
        }
    }

    pub fn get_or_insert(&mut self, hash: [u8; 32], id: XaeroID) -> XaeroID {
        if let Some(cached_id) = self.get(hash) {
            cached_id
        } else {
            self.insert(id);
            id
        }
    }

    pub fn get(&self, hash: [u8; 32]) -> Option<XaeroID> {
        // linear scan
        self.entries[..self.count]
            .iter()
            .find(|e| e.0 == hash)
            .map(|e| e.1)
    }

    pub fn insert(&mut self, id: XaeroID) {
        if N == 0 {
            return; // Can't insert anything
        }
        let key = xaero_id_hash(&id);
        if self.count < N {
            self.entries[self.count] = (
                key,
                id,
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            );
            self.count += 1;
        } else {
            // Evict oldest (round-robin)
            self.entries[self.next_eviction] = (
                key,
                id,
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            );
            self.next_eviction = (self.next_eviction + 1) % N;
        }
    }
}

pub type XaeroIdCacheXS = XaeroIdHotCache<8>; // Very small teams
pub type XaeroIdCacheS = XaeroIdHotCache<16>; // Small teams
pub type XaeroIdCacheM = XaeroIdHotCache<32>; // Medium teams
pub type XaeroIdCacheL = XaeroIdHotCache<64>; // Large teams



#[cfg(test)]
mod xaero_id_cache_tests {
    use super::*;
    use crate::{identity::XaeroIdentityManager, IdentityManager};
    use std::collections::HashSet;

    // Helper to create test XaeroIDs
    fn create_test_xaero_id() -> XaeroID {
        let manager = XaeroIdentityManager {};
        manager.new_id()
    }

    // Helper to create XaeroID with specific data for deterministic testing
    fn create_xaero_id_with_data(data: &[u8]) -> XaeroID {
        let mut id = create_test_xaero_id();
        // Modify some field to make it unique (assuming XaeroID has modifiable fields)
        if data.len() <= id.did_peer.len() {
            id.did_peer[..data.len()].copy_from_slice(data);
        }
        id
    }

    #[test]
    fn test_xaero_id_hash_consistency() {
        let id = create_test_xaero_id();

        // Same ID should produce same hash
        let hash1 = xaero_id_hash(&id);
        let hash2 = xaero_id_hash(&id);
        assert_eq!(hash1, hash2);

        // Hash should be 32 bytes
        assert_eq!(hash1.len(), 32);

        println!("✅ XaeroID hash consistency working");
    }

    #[test]
    fn test_xaero_id_hash_uniqueness() {
        let id1 = create_xaero_id_with_data(b"test_data_1");
        let id2 = create_xaero_id_with_data(b"test_data_2");

        let hash1 = xaero_id_hash(&id1);
        let hash2 = xaero_id_hash(&id2);

        // Different IDs should produce different hashes
        assert_ne!(hash1, hash2);

        println!("✅ XaeroID hash uniqueness working");
    }

    #[test]
    fn test_cache_creation() {
        let cache_xs = XaeroIdCacheXS::new();
        let cache_s = XaeroIdCacheS::new();
        let cache_m = XaeroIdCacheM::new();
        let cache_l = XaeroIdCacheL::new();

        assert_eq!(cache_xs.count, 0);
        assert_eq!(cache_s.count, 0);
        assert_eq!(cache_m.count, 0);
        assert_eq!(cache_l.count, 0);

        println!("✅ Cache creation working");
    }

    #[test]
    fn test_cache_custom_size() {
        let cache = XaeroIdHotCache::<24>::new();
        assert_eq!(cache.count, 0);
        assert_eq!(cache.next_eviction, 0);

        println!("✅ Custom cache size working");
    }

    #[test]
    fn test_basic_insert_and_get() {
        let mut cache = XaeroIdCacheS::new();
        let id = create_test_xaero_id();
        let hash = xaero_id_hash(&id);

        // Insert ID
        cache.insert(id);
        assert_eq!(cache.count, 1);

        // Get ID back
        let retrieved = cache.get(hash);
        assert!(retrieved.is_some());

        // Verify it's the same ID (compare some fields)
        let retrieved_id = retrieved.unwrap();
        assert_eq!(retrieved_id.did_peer_len, id.did_peer_len);

        println!("✅ Basic insert and get working");
    }

    #[test]
    fn test_get_nonexistent() {
        let cache = XaeroIdCacheS::new();
        let fake_hash = [42u8; 32];

        let result = cache.get(fake_hash);
        assert!(result.is_none());

        println!("✅ Get nonexistent working");
    }

    #[test]
    fn test_get_or_insert_existing() {
        let mut cache = XaeroIdCacheS::new();
        let id = create_test_xaero_id();
        let hash = xaero_id_hash(&id);

        // Insert first
        cache.insert(id);

        // get_or_insert should return existing
        let new_id = create_test_xaero_id(); // Different ID
        let result = cache.get_or_insert(hash, new_id);

        // Should return original ID, not new one
        assert_eq!(result.did_peer_len, id.did_peer_len);
        assert_eq!(cache.count, 1); // Count should not increase

        println!("✅ Get or insert existing working");
    }

    #[test]
    fn test_get_or_insert_new() {
        let mut cache = XaeroIdCacheS::new();
        let id = create_test_xaero_id();
        let hash = xaero_id_hash(&id);

        // get_or_insert on empty cache
        let result = cache.get_or_insert(hash, id);

        assert_eq!(result.did_peer_len, id.did_peer_len);
        assert_eq!(cache.count, 1);

        // Should be able to retrieve it
        let retrieved = cache.get(hash);
        assert!(retrieved.is_some());

        println!("✅ Get or insert new working");
    }

    #[test]
    fn test_multiple_inserts() {
        let mut cache = XaeroIdCacheS::new();
        let mut ids = Vec::new();
        let mut hashes = Vec::new();

        // Insert multiple different IDs
        for i in 0..5 {
            let data = format!("test_data_{}", i);
            let id = create_xaero_id_with_data(data.as_bytes());
            let hash = xaero_id_hash(&id);

            cache.insert(id);
            ids.push(id);
            hashes.push(hash);
        }

        assert_eq!(cache.count, 5);

        // Verify all can be retrieved
        for (i, hash) in hashes.iter().enumerate() {
            let retrieved = cache.get(*hash);
            assert!(retrieved.is_some(), "Failed to retrieve ID {}", i);
        }

        println!("✅ Multiple inserts working");
    }

    #[test]
    fn test_cache_eviction_round_robin() {
        let mut cache = XaeroIdHotCache::<3>::new(); // Small cache for testing eviction
        let mut ids = Vec::new();
        let mut hashes = Vec::new();

        // Fill cache to capacity
        for i in 0..3 {
            let data = format!("initial_{}", i);
            let id = create_xaero_id_with_data(data.as_bytes());
            let hash = xaero_id_hash(&id);

            cache.insert(id);
            ids.push(id);
            hashes.push(hash);
        }

        assert_eq!(cache.count, 3);
        assert_eq!(cache.next_eviction, 0);

        // Insert one more - should trigger eviction
        let new_id = create_xaero_id_with_data(b"eviction_test");
        let new_hash = xaero_id_hash(&new_id);
        cache.insert(new_id);

        // Count should stay the same
        assert_eq!(cache.count, 3);
        assert_eq!(cache.next_eviction, 1); // Should advance round-robin

        // First ID should be evicted
        assert!(cache.get(hashes[0]).is_none());
        // New ID should be findable
        assert!(cache.get(new_hash).is_some());
        // Other IDs should still be there
        assert!(cache.get(hashes[1]).is_some());
        assert!(cache.get(hashes[2]).is_some());

        println!("✅ Cache eviction round-robin working");
    }

    #[test]
    fn test_cache_eviction_multiple_rounds() {
        let mut cache = XaeroIdHotCache::<2>::new(); // Very small cache

        // Insert more items than cache capacity
        for i in 0..5 {
            let data = format!("round_{}", i);
            let id = create_xaero_id_with_data(data.as_bytes());
            cache.insert(id);
        }

        // Should only have 2 items (cache capacity)
        assert_eq!(cache.count, 2);

        // next_eviction should have wrapped around
        assert_eq!(cache.next_eviction, 1); // (5 - 2) % 2 = 1

        println!("✅ Multiple round eviction working");
    }

    #[test]
    fn test_duplicate_insert() {
        let mut cache = XaeroIdCacheS::new();
        let id = create_test_xaero_id();

        // Insert same ID twice
        cache.insert(id);
        cache.insert(id);

        // Should have 2 entries (duplicates allowed)
        assert_eq!(cache.count, 2);

        let hash = xaero_id_hash(&id);
        // get() should find the first occurrence
        assert!(cache.get(hash).is_some());

        println!("✅ Duplicate insert handling working");
    }

    #[test]
    fn test_hash_collision_resistance() {
        let mut cache = XaeroIdCacheL::new();
        let mut unique_hashes = HashSet::new();

        // Generate many IDs and verify hash uniqueness
        for i in 0..50 {
            let data = format!("collision_test_{}", i);
            let id = create_xaero_id_with_data(data.as_bytes());
            let hash = xaero_id_hash(&id);

            // Hash should be unique
            assert!(unique_hashes.insert(hash), "Hash collision detected at iteration {}", i);

            cache.insert(id);
        }

        assert_eq!(cache.count, 50);
        println!("✅ Hash collision resistance working");
    }

    #[test]
    fn test_cache_memory_layout() {
        let cache = XaeroIdCacheM::new();

        // Verify alignment
        let cache_ptr = &cache as *const _ as usize;
        assert_eq!(cache_ptr % 64, 0, "Cache not aligned to 64-byte boundary");

        // Verify size is reasonable
        let cache_size = std::mem::size_of::<XaeroIdCacheM>();
        println!("Cache size: {} bytes", cache_size);

        // Should be roughly: 32 * (32 + XaeroID_size + 8) + overhead
        // This is just a sanity check, actual size depends on XaeroID
        assert!(cache_size > 1000, "Cache suspiciously small");
        assert!(cache_size < 1_000_000, "Cache suspiciously large");

        println!("✅ Cache memory layout working");
    }

    #[test]
    fn test_linear_scan_performance() {
        let mut cache = XaeroIdCacheL::new();
        let mut test_hashes = Vec::new();

        // Fill cache
        for i in 0..64 {
            let data = format!("perf_test_{}", i);
            let id = create_xaero_id_with_data(data.as_bytes());
            let hash = xaero_id_hash(&id);

            cache.insert(id);
            test_hashes.push(hash);
        }

        // Time linear scans (this is more of a sanity check)
        let start = std::time::Instant::now();

        for hash in &test_hashes {
            let _result = cache.get(*hash);
        }

        let duration = start.elapsed();

        // This should be very fast
        assert!(duration.as_millis() < 10, "Linear scan too slow: {:?}", duration);

        println!("✅ Linear scan performance: {:?} for 64 lookups", duration);
    }

    #[test]
    fn test_type_aliases() {
        // Verify all type aliases work
        let _xs = XaeroIdCacheXS::new();
        let _s = XaeroIdCacheS::new();
        let _m = XaeroIdCacheM::new();
        let _l = XaeroIdCacheL::new();

        // Verify they have expected capacities by filling them
        let mut xs = XaeroIdCacheXS::new();
        for i in 0..10 {
            let id = create_xaero_id_with_data(&[i]);
            xs.insert(id);
        }
        assert_eq!(xs.count, 8); // Should cap at XS size

        println!("✅ Type aliases working");
    }

    // Mock storage for testing trait
    struct MockStorage {
        pub stored_items: Vec<([u8; 32], XaeroID)>,
    }

    impl XaeroIdStorage for MockStorage {
        fn flush(&mut self, hash: [u8; 32], id: &XaeroID) {
            self.stored_items.push((hash, *id));
        }
    }

    #[test]
    fn test_storage_trait() {
        let mut storage = MockStorage {
            stored_items: Vec::new(),
        };

        let id = create_test_xaero_id();
        let hash = xaero_id_hash(&id);

        storage.flush(hash, &id);

        assert_eq!(storage.stored_items.len(), 1);
        assert_eq!(storage.stored_items[0].0, hash);

        println!("✅ Storage trait working");
    }

    #[test]
    fn test_zero_size_cache() {
        let mut cache = XaeroIdHotCache::<0>::new();
        let id = create_test_xaero_id();

        // Insert should not crash
        cache.insert(id);
        assert_eq!(cache.count, 0); // Should stay 0

        // Get should return None
        let hash = xaero_id_hash(&id);
        assert!(cache.get(hash).is_none());

        println!("✅ Zero size cache handling working");
    }
}