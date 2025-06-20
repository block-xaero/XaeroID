use rusted_ring::{EventAllocator, EventSize, PooledEvent, RingPtr};

use crate::XaeroID;

pub static XAERO_ID_EVENT_BASE: u8 = 108;
impl<const SIZE: usize> From<PooledEvent<SIZE>> for XaeroID {
    fn from(value: PooledEvent<SIZE>) -> Self {
        *bytemuck::from_bytes::<XaeroID>(&value.data)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    #[error(
        "Data too large for ring buffer pools: {data_len} bytes > {max_pool_size} bytes. Size \
         your events to fit XL pool (16KB) or smaller."
    )]
    TooLarge {
        data_len: usize,
        max_pool_size: usize,
    },
    #[error("Pool allocation failed: {0}")]
    AllocationFailed(String),
}

pub struct XaeroIDPoolManager {
    allocator: &'static EventAllocator,
}

impl XaeroIDPoolManager {
    // SAFETY: This is safe because:
    // 1. RingPtr<PooledEvent<SIZE>> and RingPtr<XaeroID> have identical memory layouts
    // 2. Both point to the same underlying memory buffer
    // 3. XaeroID is accessed via bytemuck::from_bytes from the same buffer data
    // 4. Reference counting behavior is preserved
    pub fn allocate_xaero_id(&self, xaero_id: XaeroID) -> Result<RingPtr<XaeroID>, PoolError> {
        // Convert XaeroID to bytes
        let bytes = bytemuck::bytes_of(&xaero_id);
        let estimate = EventAllocator::estimate_size(bytes.len());
        match estimate {
            EventSize::XS => {
                let allocated_pooled_event = self
                    .allocator
                    .allocate_xs_event(bytes, XAERO_ID_EVENT_BASE as u32);
                match allocated_pooled_event {
                    Ok(allocated_pooled_event) => Ok(unsafe {
                        std::mem::transmute::<RingPtr<PooledEvent<64>>, RingPtr<XaeroID>>(
                            allocated_pooled_event,
                        )
                    }),
                    Err(e) => Err(PoolError::AllocationFailed(e.to_string())),
                }
            }
            EventSize::S => {
                let allocated_pooled_event = self
                    .allocator
                    .allocate_s_event(bytes, XAERO_ID_EVENT_BASE as u32);
                match allocated_pooled_event {
                    Ok(allocated_pooled_event) => Ok(unsafe {
                        std::mem::transmute::<RingPtr<PooledEvent<256>>, RingPtr<XaeroID>>(
                            allocated_pooled_event,
                        )
                    }),
                    Err(e) => Err(PoolError::AllocationFailed(e.to_string())),
                }
            }
            EventSize::M => {
                let allocated_pooled_event = self
                    .allocator
                    .allocate_m_event(bytes, XAERO_ID_EVENT_BASE as u32);
                match allocated_pooled_event {
                    Ok(allocated_pooled_event) => Ok(unsafe {
                        std::mem::transmute::<RingPtr<PooledEvent<1024>>, RingPtr<XaeroID>>(
                            allocated_pooled_event,
                        )
                    }),
                    Err(e) => Err(PoolError::AllocationFailed(e.to_string())),
                }
            }
            EventSize::L => {
                let allocated_pooled_event = self
                    .allocator
                    .allocate_l_event(bytes, XAERO_ID_EVENT_BASE as u32);
                match allocated_pooled_event {
                    Ok(allocated_pooled_event) => Ok(unsafe {
                        std::mem::transmute::<RingPtr<PooledEvent<4096>>, RingPtr<XaeroID>>(
                            allocated_pooled_event,
                        )
                    }),
                    Err(e) => Err(PoolError::AllocationFailed(e.to_string())),
                }
            }
            EventSize::XL => {
                let allocated_pooled_event = self
                    .allocator
                    .allocate_xl_event(bytes, XAERO_ID_EVENT_BASE as u32);
                match allocated_pooled_event {
                    Ok(allocated_pooled_event) => Ok(unsafe {
                        std::mem::transmute::<RingPtr<PooledEvent<16384>>, RingPtr<XaeroID>>(
                            allocated_pooled_event,
                        )
                    }),
                    Err(e) => Err(PoolError::AllocationFailed(e.to_string())),
                }
            }
            EventSize::XXL => panic!("XXL pools are not supported"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use super::*;
    use crate::{identity::XaeroIdentityManager, IdentityManager};

    // Test allocator - you'll need to adapt this to your actual initialization
    static TEST_ALLOCATOR: OnceLock<EventAllocator> = OnceLock::new();

    fn get_test_allocator() -> &'static EventAllocator {
        TEST_ALLOCATOR.get_or_init(EventAllocator::new)
    }

    fn create_test_xaero_id() -> XaeroID {
        let manager = XaeroIdentityManager {};
        manager.new_id()
    }

    #[test]
    fn test_xaero_id_size_detection() {
        let xaero_id = create_test_xaero_id();
        let bytes = bytemuck::bytes_of(&xaero_id);

        println!("XaeroID size: {} bytes", bytes.len());

        let estimated_size = EventAllocator::estimate_size(bytes.len());
        println!("Estimated pool size: {:?}", estimated_size);

        // XaeroID should fit in L pool (4096 bytes) or larger
        assert!(matches!(estimated_size, EventSize::L | EventSize::XL));
    }

    #[test]
    fn test_allocate_xaero_id_success() {
        let allocator = get_test_allocator();
        let manager = XaeroIDPoolManager { allocator };

        let xaero_id = create_test_xaero_id();
        let original_did_len = xaero_id.did_peer_len;

        // Allocate XaeroID in ring buffer
        let ring_ptr = manager
            .allocate_xaero_id(xaero_id)
            .expect("Failed to allocate XaeroID");

        // Verify we can dereference and access data
        let retrieved_id = &*ring_ptr;
        assert_eq!(retrieved_id.did_peer_len, original_did_len);
        assert_ne!(retrieved_id.did_peer, [0u8; 897]); // Should have real data
    }

    #[test]
    fn test_multiple_xaero_id_allocations() {
        let allocator = get_test_allocator();
        let manager = XaeroIDPoolManager { allocator };

        let mut ring_ptrs = Vec::new();

        // Allocate multiple XaeroIDs
        for i in 0..5 {
            let xaero_id = create_test_xaero_id();
            let ring_ptr = manager
                .allocate_xaero_id(xaero_id)
                .unwrap_or_else(|_| panic!("Failed to allocate XaeroID {}", i));
            ring_ptrs.push(ring_ptr);
        }

        // Verify all are different and accessible
        for (i, ring_ptr) in ring_ptrs.iter().enumerate() {
            let retrieved_id = &**ring_ptr;
            assert_ne!(
                retrieved_id.did_peer, [0u8; 897],
                "XaeroID {} has empty data",
                i
            );

            // Each should have valid did_peer_len
            assert_eq!(
                retrieved_id.did_peer_len, 897,
                "XaeroID {} has wrong did_peer_len",
                i
            );
        }
    }

    #[test]
    fn test_xaero_id_data_integrity() {
        let allocator = get_test_allocator();
        let manager = XaeroIDPoolManager { allocator };

        let original_xaero_id = create_test_xaero_id();

        // Store original data for comparison
        let original_did_peer = original_xaero_id.did_peer;
        let original_did_len = original_xaero_id.did_peer_len;
        let original_secret_key = original_xaero_id.secret_key;

        // Allocate and retrieve
        let ring_ptr = manager
            .allocate_xaero_id(original_xaero_id)
            .expect("Failed to allocate XaeroID");

        let retrieved_id = &*ring_ptr;

        // Verify data integrity
        assert_eq!(retrieved_id.did_peer, original_did_peer);
        assert_eq!(retrieved_id.did_peer_len, original_did_len);
        assert_eq!(retrieved_id.secret_key, original_secret_key);

        // Verify credential data
        assert_eq!(
            retrieved_id.credential.vc_len,
            original_xaero_id.credential.vc_len
        );
        assert_eq!(
            retrieved_id.credential.proof_count,
            original_xaero_id.credential.proof_count
        );
    }

    #[test]
    fn test_ring_ptr_clone_and_reference_counting() {
        let allocator = get_test_allocator();
        let manager = XaeroIDPoolManager { allocator };

        let xaero_id = create_test_xaero_id();
        let original_did_len = xaero_id.did_peer_len;

        // Allocate XaeroID
        let ring_ptr1 = manager
            .allocate_xaero_id(xaero_id)
            .expect("Failed to allocate XaeroID");

        // Clone RingPtr (should increment reference count)
        let ring_ptr2 = ring_ptr1.clone();
        let ring_ptr3 = ring_ptr1.clone();

        // All should point to same data
        assert_eq!(ring_ptr1.did_peer_len, original_did_len);
        assert_eq!(ring_ptr2.did_peer_len, original_did_len);
        assert_eq!(ring_ptr3.did_peer_len, original_did_len);

        // Data should be identical (same memory location)
        let ptr1_data = &ring_ptr1.did_peer as *const _;
        let ptr2_data = &ring_ptr2.did_peer as *const _;
        let ptr3_data = &ring_ptr3.did_peer as *const _;

        assert_eq!(ptr1_data, ptr2_data);
        assert_eq!(ptr2_data, ptr3_data);
    }

    #[test]
    fn test_xaero_id_from_pooled_event_conversion() {
        let allocator = get_test_allocator();
        let manager = XaeroIDPoolManager { allocator };

        let original_xaero_id = create_test_xaero_id();
        let original_bytes = bytemuck::bytes_of(&original_xaero_id);

        // Allocate XaeroID
        let ring_ptr = manager
            .allocate_xaero_id(original_xaero_id)
            .expect("Failed to allocate XaeroID");

        // Test that From<PooledEvent> trait works
        // Note: This is more of a compile-time test since the conversion happens in transmute
        let retrieved_id = &*ring_ptr;
        let retrieved_bytes = bytemuck::bytes_of(retrieved_id);

        // Bytes should be identical
        assert_eq!(original_bytes, retrieved_bytes);
    }

    #[test]
    fn test_concurrent_access() {
        use std::{sync::Arc, thread};

        let allocator = get_test_allocator();
        let manager = Arc::new(XaeroIDPoolManager { allocator });

        let mut handles = vec![];

        // Spawn multiple threads allocating XaeroIDs
        for thread_id in 0..4 {
            let manager_clone = manager.clone();
            let handle = thread::spawn(move || {
                let mut results = vec![];

                for i in 0..3 {
                    let xaero_id = create_test_xaero_id();
                    let ring_ptr = manager_clone
                        .allocate_xaero_id(xaero_id)
                        .unwrap_or_else(|_| panic!("Thread {} failed allocation {}", thread_id, i));

                    // Verify data integrity
                    let retrieved_id = &*ring_ptr;
                    assert_eq!(retrieved_id.did_peer_len, 897);
                    assert_ne!(retrieved_id.did_peer, [0u8; 897]);

                    results.push(ring_ptr);
                }

                results
            });
            handles.push(handle);
        }

        // Wait for all threads and collect results
        let mut all_results = vec![];
        for handle in handles {
            let thread_results = handle.join().expect("Thread panicked");
            all_results.extend(thread_results);
        }

        // Verify we got all allocations
        assert_eq!(all_results.len(), 12); // 4 threads × 3 allocations

        // Verify all data is accessible
        for (i, ring_ptr) in all_results.iter().enumerate() {
            let retrieved_id = &**ring_ptr;
            assert_eq!(
                retrieved_id.did_peer_len, 897,
                "Result {} has wrong did_peer_len",
                i
            );
        }
    }

    #[test]
    fn test_pool_error_handling() {
        let allocator = get_test_allocator();
        let manager = XaeroIDPoolManager { allocator };

        // Test with a valid XaeroID first to ensure normal operation works
        let valid_xaero_id = create_test_xaero_id();
        let result = manager.allocate_xaero_id(valid_xaero_id);
        assert!(result.is_ok(), "Valid XaeroID allocation should succeed");

        // Note: Testing actual pool exhaustion would require filling the entire pool
        // which might be expensive for unit tests. In practice, you'd want integration tests for
        // this.
    }

    #[test]
    fn test_xaero_id_round_trip() {
        let allocator = get_test_allocator();
        let manager = XaeroIDPoolManager { allocator };

        // Create XaeroID with known data
        let mut original_xaero_id = create_test_xaero_id();

        // Set some specific test values
        original_xaero_id.credential.vc_len = 100;
        original_xaero_id.credential.proof_count = 2;

        // Round trip through ring buffer
        let ring_ptr = manager
            .allocate_xaero_id(original_xaero_id)
            .expect("Failed to allocate XaeroID");

        let retrieved_id = &*ring_ptr;

        // Verify round trip integrity
        assert_eq!(retrieved_id.did_peer_len, original_xaero_id.did_peer_len);
        assert_eq!(retrieved_id.credential.vc_len, 100);
        assert_eq!(retrieved_id.credential.proof_count, 2);

        // Verify byte-level equality
        let original_bytes = bytemuck::bytes_of(&original_xaero_id);
        let retrieved_bytes = bytemuck::bytes_of(retrieved_id);
        assert_eq!(original_bytes, retrieved_bytes);
    }

    #[test]
    fn test_memory_layout_assumptions() {
        // Verify our assumptions about XaeroID size and alignment
        use std::mem;

        let xaero_id_size = mem::size_of::<XaeroID>();
        let xaero_id_align = mem::align_of::<XaeroID>();

        println!("XaeroID size: {} bytes", xaero_id_size);
        println!("XaeroID alignment: {} bytes", xaero_id_align);

        // Should fit in L pool (4096 bytes) or XL pool (16384 bytes)
        assert!(xaero_id_size <= 16384, "XaeroID too large for XL pool");

        // Should be properly aligned for bytemuck operations
        assert!(xaero_id_align <= 8, "XaeroID alignment too large");

        // Verify it's a valid Pod type
        let test_xaero_id = create_test_xaero_id();
        let _bytes = bytemuck::bytes_of(&test_xaero_id); // Should not panic
    }
}
