use rustc_hash::FxHashMap;

use crate::core::mem_access::{MemAccessIndex, MemRw};
use crate::core::reg_checkpoint::RegCheckpoints;
use crate::core::scanner::{DepsStorage, MemLastDef, PairSplitDeps};
use crate::index::line_index::LineIndex;

use super::mem_access::{FlatMemAccess, FlatMemAccessRecord, MEM_RW_READ, MEM_RW_WRITE};
use super::reg_checkpoints::{FlatRegCheckpoints, REG_COUNT};
use super::deps::FlatDeps;
use super::mem_last_def::FlatMemLastDef;
use super::pair_split::FlatPairSplit;
use super::bitvec::FlatBitVec;
use super::line_index::LineIndexArchive;

/// Convert a `MemAccessIndex` (HashMap-backed) to `FlatMemAccess` (sorted CSR format).
pub fn mem_access_to_flat(idx: &MemAccessIndex) -> FlatMemAccess {
    // Collect all (addr, record) pairs from iter_all, group by addr
    let mut grouped: Vec<(u64, Vec<&crate::core::mem_access::MemAccessRecord>)> = {
        let mut map: std::collections::BTreeMap<u64, Vec<&crate::core::mem_access::MemAccessRecord>> =
            std::collections::BTreeMap::new();
        for (addr, rec) in idx.iter_all() {
            map.entry(addr).or_default().push(rec);
        }
        map.into_iter().collect()
    };

    // Sort within each group by seq for deterministic output
    for (_, recs) in &mut grouped {
        recs.sort_by_key(|r| r.seq);
    }

    let total_addrs = grouped.len();
    let total_records: usize = grouped.iter().map(|(_, v)| v.len()).sum();

    let mut addrs = Vec::with_capacity(total_addrs);
    let mut offsets = Vec::with_capacity(total_addrs + 1);
    let mut records = Vec::with_capacity(total_records);

    offsets.push(0u32);

    for (addr, recs) in &grouped {
        addrs.push(*addr);
        for rec in recs {
            records.push(FlatMemAccessRecord {
                insn_addr: rec.insn_addr,
                data: rec.data,
                seq: rec.seq,
                size: rec.size,
                rw: match rec.rw {
                    MemRw::Read => MEM_RW_READ,
                    MemRw::Write => MEM_RW_WRITE,
                },
                _pad: [0; 2],
            });
        }
        offsets.push(records.len() as u32);
    }

    FlatMemAccess { addrs, offsets, records }
}

/// Convert `RegCheckpoints` to `FlatRegCheckpoints` (flattened u64 array).
pub fn reg_checkpoints_to_flat(ckpts: &RegCheckpoints) -> FlatRegCheckpoints {
    let count = ckpts.snapshots.len() as u32;
    let mut data = Vec::with_capacity(ckpts.snapshots.len() * REG_COUNT);
    for snap in &ckpts.snapshots {
        data.extend_from_slice(&snap.0);
    }
    FlatRegCheckpoints {
        interval: ckpts.interval,
        count,
        data,
    }
}

/// Convert `DepsStorage` to `FlatDeps` (CSR format with optional patches).
pub fn deps_to_flat(deps: &DepsStorage) -> FlatDeps {
    match deps {
        DepsStorage::Single(cd) => {
            // Single chunk: trivial — chunk starts at line 0, offsets_start=0, data_start=0
            // CompactDeps has N offsets for N rows; DepsView needs N+1 (CSR with sentinel).
            let mut all_offsets = cd.offsets_slice().to_vec();
            let all_data = cd.data_slice().to_vec();
            // Add sentinel pointing past the last element
            all_offsets.push(all_data.len() as u32);
            FlatDeps {
                chunk_start_lines: vec![0u32],
                chunk_offsets_start: vec![0u32],
                chunk_data_start: vec![0u32],
                all_offsets,
                all_data,
                patch_lines: vec![],
                patch_offsets: vec![],
                patch_data: vec![],
            }
        }
        DepsStorage::Chunked { chunks, chunk_start_lines, patch_groups } => {
            let num_chunks = chunks.len();
            let mut chunk_offsets_start = Vec::with_capacity(num_chunks);
            let mut chunk_data_start = Vec::with_capacity(num_chunks);
            let mut all_offsets = Vec::new();
            let mut all_data = Vec::new();

            for chunk in chunks {
                chunk_offsets_start.push(all_offsets.len() as u32);
                chunk_data_start.push(all_data.len() as u32);
                all_offsets.extend_from_slice(chunk.offsets_slice());
                // Add sentinel pointing past the last element (relative to chunk data start)
                all_offsets.push(chunk.data_slice().len() as u32);
                all_data.extend_from_slice(chunk.data_slice());
            }

            // Build patch CSR: patch_groups is Vec<(u32, Vec<u32>)> sorted by line
            let mut patch_lines = Vec::with_capacity(patch_groups.len());
            let mut patch_offsets = Vec::with_capacity(patch_groups.len() + 1);
            let mut patch_data: Vec<u32> = Vec::new();

            patch_offsets.push(0u32);
            for (line, deps_vec) in patch_groups {
                patch_lines.push(*line);
                patch_data.extend_from_slice(deps_vec);
                patch_offsets.push(patch_data.len() as u32);
            }

            FlatDeps {
                chunk_start_lines: chunk_start_lines.clone(),
                chunk_offsets_start,
                chunk_data_start,
                all_offsets,
                all_data,
                patch_lines,
                patch_offsets,
                patch_data,
            }
        }
    }
}

/// Convert `MemLastDef` to `FlatMemLastDef` (three parallel sorted arrays).
///
/// Panics if `mld` is still in `Map` form — call `compact()` first.
pub fn mem_last_def_to_flat(mld: &MemLastDef) -> FlatMemLastDef {
    match mld {
        MemLastDef::Sorted(v) => {
            let mut addrs = Vec::with_capacity(v.len());
            let mut lines = Vec::with_capacity(v.len());
            let mut values = Vec::with_capacity(v.len());
            for (addr, line, val) in v {
                addrs.push(*addr);
                lines.push(*line);
                values.push(*val);
            }
            FlatMemLastDef { addrs, lines, values }
        }
        MemLastDef::Map(_) => {
            panic!("mem_last_def_to_flat: MemLastDef must be compacted (Sorted) before caching. Call compact() first.");
        }
    }
}

/// Convert `FxHashMap<u32, PairSplitDeps>` to `FlatPairSplit` (sorted CSR).
pub fn pair_split_to_flat(ps: &FxHashMap<u32, PairSplitDeps>) -> FlatPairSplit {
    // Sort entries by key
    let mut sorted: Vec<(u32, &PairSplitDeps)> = ps.iter().map(|(&k, v)| (k, v)).collect();
    sorted.sort_unstable_by_key(|(k, _)| *k);

    let n = sorted.len();
    let mut keys = Vec::with_capacity(n);
    // seg_offsets: n*3 + 1 entries
    let mut seg_offsets = Vec::with_capacity(n * 3 + 1);
    let mut data: Vec<u32> = Vec::new();

    for (key, entry) in &sorted {
        keys.push(*key);
        // Per entry layout: [shared_start, half1_start, half2_start, end]
        // but they share the sentinel with the next entry, so per entry we push 3 values
        // (the 4th sentinel is the first value of the next entry or the final sentinel).
        // Actually the layout is a flat array: for entry i:
        //   base = i * 3
        //   shared   = data[seg_offsets[base]   .. seg_offsets[base+1]]
        //   half1    = data[seg_offsets[base+1]  .. seg_offsets[base+2]]
        //   half2    = data[seg_offsets[base+2]  .. seg_offsets[base+3]]
        // So we push 3 offsets per entry (start of shared, start of half1, start of half2)
        // and a final sentinel at the end.
        seg_offsets.push(data.len() as u32);          // shared start
        data.extend_from_slice(entry.shared.as_slice());
        seg_offsets.push(data.len() as u32);          // half1 start
        data.extend_from_slice(entry.half1_deps.as_slice());
        seg_offsets.push(data.len() as u32);          // half2 start
        data.extend_from_slice(entry.half2_deps.as_slice());
    }
    // Final sentinel = total data length (the "end" of the last entry's half2)
    seg_offsets.push(data.len() as u32);

    FlatPairSplit { keys, seg_offsets, data }
}

/// Convert a `bitvec::BitVec` (Lsb0 order) to `FlatBitVec`.
pub fn bitvec_to_flat(bv: &bitvec::prelude::BitVec) -> FlatBitVec {
    let len = bv.len() as u32;
    // as_raw_slice() returns &[usize]; reinterpret as bytes
    let raw: &[usize] = bv.as_raw_slice();
    // SAFETY: usize is valid to reinterpret as bytes; all bits are initialised.
    let byte_data: &[u8] = unsafe {
        core::slice::from_raw_parts(
            raw.as_ptr() as *const u8,
            raw.len() * std::mem::size_of::<usize>(),
        )
    };
    // Only keep the bytes actually needed to hold `len` bits
    let needed_bytes = (len as usize + 7) / 8;
    FlatBitVec {
        data: byte_data[..needed_bytes].to_vec(),
        len,
    }
}

/// Convert a `LineIndex` to `LineIndexArchive` (for cache serialization).
pub fn line_index_to_archive(li: &LineIndex) -> LineIndexArchive {
    LineIndexArchive {
        sampled_offsets: li.sampled_offsets().to_vec(),
        total: li.total_lines(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::mem_access::{MemAccessIndex, MemAccessRecord, MemRw};
    use crate::core::reg_checkpoint::RegCheckpoints;
    use crate::core::scanner::{CompactDeps, DepsStorage, MemLastDef, PairSplitDeps};
    use bitvec::prelude::BitVec;

    // ── mem_access ──────────────────────────────────────────────────────────

    #[test]
    fn test_mem_access_empty() {
        let idx = MemAccessIndex::new();
        let flat = mem_access_to_flat(&idx);
        let view = flat.view();
        assert_eq!(view.total_addresses(), 0);
        assert_eq!(view.total_records(), 0);
        assert!(view.query(0x1000).is_none());
    }

    #[test]
    fn test_mem_access_round_trip() {
        let mut idx = MemAccessIndex::new();
        idx.add(0x1000, MemAccessRecord { seq: 0, insn_addr: 0x100, rw: MemRw::Write, data: 0x42, size: 4 });
        idx.add(0x1000, MemAccessRecord { seq: 5, insn_addr: 0x104, rw: MemRw::Read,  data: 0x43, size: 4 });
        idx.add(0x2000, MemAccessRecord { seq: 10, insn_addr: 0x200, rw: MemRw::Write, data: 0xFF, size: 1 });

        let flat = mem_access_to_flat(&idx);
        let view = flat.view();

        assert_eq!(view.total_addresses(), 2);
        assert_eq!(view.total_records(), 3);

        // 0x1000 has 2 records sorted by seq
        let recs = view.query(0x1000).unwrap();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].seq, 0);
        assert_eq!(recs[0].data, 0x42);
        assert!(recs[0].is_write());
        assert_eq!(recs[1].seq, 5);
        assert!(recs[1].is_read());

        // 0x2000 has 1 record
        let recs2 = view.query(0x2000).unwrap();
        assert_eq!(recs2.len(), 1);
        assert_eq!(recs2[0].seq, 10);

        // miss
        assert!(view.query(0x9999).is_none());
    }

    #[test]
    fn test_mem_access_sorted_addrs() {
        let mut idx = MemAccessIndex::new();
        // Insert in non-sorted order
        idx.add(0x3000, MemAccessRecord { seq: 1, insn_addr: 0x300, rw: MemRw::Read, data: 1, size: 1 });
        idx.add(0x1000, MemAccessRecord { seq: 2, insn_addr: 0x100, rw: MemRw::Read, data: 2, size: 1 });
        idx.add(0x2000, MemAccessRecord { seq: 3, insn_addr: 0x200, rw: MemRw::Read, data: 3, size: 1 });

        let flat = mem_access_to_flat(&idx);
        // addrs must be sorted for binary search
        assert!(flat.addrs.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(flat.view().query(0x1000).unwrap().len(), 1);
        assert_eq!(flat.view().query(0x2000).unwrap().len(), 1);
        assert_eq!(flat.view().query(0x3000).unwrap().len(), 1);
    }

    // ── reg_checkpoints ─────────────────────────────────────────────────────

    #[test]
    fn test_reg_checkpoints_empty() {
        let ckpts = RegCheckpoints::new(100);
        let flat = reg_checkpoints_to_flat(&ckpts);
        assert_eq!(flat.interval, 100);
        assert_eq!(flat.count, 0);
        assert!(flat.data.is_empty());
        assert!(flat.view().nearest_before(0).is_none());
    }

    #[test]
    fn test_reg_checkpoints_round_trip() {
        use crate::core::types::RegId;
        let mut ckpts = RegCheckpoints::new(100);

        let mut vals0 = [0u64; RegId::COUNT];
        for i in 0..RegId::COUNT { vals0[i] = i as u64 * 10; }
        ckpts.save_checkpoint(&vals0);

        let mut vals1 = [0u64; RegId::COUNT];
        for i in 0..RegId::COUNT { vals1[i] = i as u64 * 20; }
        ckpts.save_checkpoint(&vals1);

        let flat = reg_checkpoints_to_flat(&ckpts);
        assert_eq!(flat.interval, 100);
        assert_eq!(flat.count, 2);
        assert_eq!(flat.data.len(), 2 * REG_COUNT);

        let view = flat.view();
        let (seq0, regs0) = view.nearest_before(0).unwrap();
        assert_eq!(seq0, 0);
        assert_eq!(regs0[0], 0);
        assert_eq!(regs0[1], 10);

        let (seq1, regs1) = view.nearest_before(100).unwrap();
        assert_eq!(seq1, 100);
        assert_eq!(regs1[0], 0);
        assert_eq!(regs1[1], 20);
    }

    // ── deps ────────────────────────────────────────────────────────────────

    #[test]
    fn test_deps_single_round_trip() {
        // Build a Single DepsStorage with 3 lines
        // Line 0 → [10, 20], Line 1 → [30], Line 2 → []
        let mut cd = CompactDeps::with_capacity(3, 3);
        cd.start_row(); cd.push_unique(10); cd.push_unique(20);
        cd.start_row(); cd.push_unique(30);
        cd.start_row();
        // finalize sentinel
        // CompactDeps doesn't auto-add sentinel; offsets has 3 entries, data is addressed via row()
        // Actually we need to check how the flat view works for Single:
        // DepsView.row() uses all_offsets[offsets_base + local] and all_offsets[offsets_base + local + 1]
        // So we need N+1 offsets for N rows. Let's verify.
        // cd.offsets = [0, 2, 3] (start_row pushes current data.len())
        // The row(2) call: start=offsets[2]=3, end uses offsets[3] which doesn't exist → uses data.len()=3
        // But FlatDeps.row() uses all_offsets[base+local+1] so we need the sentinel.
        // So for FlatDeps to work, we need an extra sentinel in all_offsets.
        // Let's add it explicitly.
        let cd_final = CompactDeps::from_raw(
            vec![0u32, 2, 3, 3], // offsets with sentinel
            vec![10u32, 20, 30],
        );
        let ds = DepsStorage::single(cd_final);
        let flat = deps_to_flat(&ds);
        let view = flat.view();
        assert_eq!(view.row(0), &[10u32, 20]);
        assert_eq!(view.row(1), &[30u32]);
        assert_eq!(view.row(2), &[] as &[u32]);
    }

    #[test]
    fn test_deps_chunked_round_trip() {
        // Chunk 0: lines [0, 1] → offsets [0,3,4], data [1,2,3,4]
        // Chunk 1: lines [5, 6] → offsets [0,2,3], data [7,8,9]
        // patch: line 1 → [100], line 5 → [200, 201]
        let cd0 = CompactDeps::from_raw(vec![0u32, 3, 4], vec![1u32, 2, 3, 4]);
        let cd1 = CompactDeps::from_raw(vec![0u32, 2, 3], vec![7u32, 8, 9]);

        let ds = DepsStorage::Chunked {
            chunks: vec![cd0, cd1],
            chunk_start_lines: vec![0u32, 5],
            patch_groups: vec![(1u32, vec![100u32]), (5u32, vec![200u32, 201])],
        };

        let flat = deps_to_flat(&ds);
        let view = flat.view();

        assert_eq!(view.row(0), &[1u32, 2, 3]);
        assert_eq!(view.row(1), &[4u32]);
        assert_eq!(view.row(5), &[7u32, 8]);
        assert_eq!(view.row(6), &[9u32]);

        assert_eq!(view.patch_row(1), &[100u32]);
        assert_eq!(view.patch_row(5), &[200u32, 201]);
        assert_eq!(view.patch_row(0), &[] as &[u32]);
    }

    // ── mem_last_def ─────────────────────────────────────────────────────────

    #[test]
    fn test_mem_last_def_round_trip() {
        let mld = MemLastDef::Sorted(vec![
            (0x1000, 5, 0xAA),
            (0x2000, 10, 0xBB),
            (0x3000, 15, 0xCC),
        ]);
        let flat = mem_last_def_to_flat(&mld);
        let view = flat.view();
        assert_eq!(view.get(&0x1000), Some((5, 0xAA)));
        assert_eq!(view.get(&0x2000), Some((10, 0xBB)));
        assert_eq!(view.get(&0x3000), Some((15, 0xCC)));
        assert_eq!(view.get(&0x9999), None);
    }

    #[test]
    fn test_mem_last_def_empty() {
        let mld = MemLastDef::Sorted(vec![]);
        let flat = mem_last_def_to_flat(&mld);
        assert_eq!(flat.view().get(&0x1000), None);
    }

    #[test]
    #[should_panic(expected = "must be compacted")]
    fn test_mem_last_def_panics_on_map() {
        let mld = MemLastDef::Map(rustc_hash::FxHashMap::default());
        let _ = mem_last_def_to_flat(&mld);
    }

    // ── pair_split ───────────────────────────────────────────────────────────

    #[test]
    fn test_pair_split_empty() {
        let ps: FxHashMap<u32, PairSplitDeps> = FxHashMap::default();
        let flat = pair_split_to_flat(&ps);
        let view = flat.view();
        assert!(!view.contains_key(&0));
        assert!(view.get(&0).is_none());
    }

    #[test]
    fn test_pair_split_round_trip() {
        use smallvec::smallvec;
        let mut ps: FxHashMap<u32, PairSplitDeps> = FxHashMap::default();
        ps.insert(10, PairSplitDeps {
            shared: smallvec![1, 2],
            half1_deps: smallvec![3],
            half2_deps: smallvec![4, 5],
        });
        ps.insert(20, PairSplitDeps {
            shared: smallvec![],
            half1_deps: smallvec![6],
            half2_deps: smallvec![],
        });

        let flat = pair_split_to_flat(&ps);
        let view = flat.view();

        let e10 = view.get(&10).unwrap();
        assert_eq!(e10.shared, &[1u32, 2]);
        assert_eq!(e10.half1_deps, &[3u32]);
        assert_eq!(e10.half2_deps, &[4u32, 5]);

        let e20 = view.get(&20).unwrap();
        assert_eq!(e20.shared, &[] as &[u32]);
        assert_eq!(e20.half1_deps, &[6u32]);
        assert_eq!(e20.half2_deps, &[] as &[u32]);

        assert!(!view.contains_key(&99));
        assert!(view.get(&99).is_none());
    }

    // ── bitvec ───────────────────────────────────────────────────────────────

    #[test]
    fn test_bitvec_empty() {
        let bv: BitVec = BitVec::new();
        let flat = bitvec_to_flat(&bv);
        assert_eq!(flat.len, 0);
        assert!(flat.data.is_empty());
        let view = flat.view();
        assert!(view.is_empty());
    }

    #[test]
    fn test_bitvec_round_trip() {
        let bits = [true, false, true, true, false, false, false, true, false, true];
        let mut bv: BitVec = BitVec::new();
        for &b in &bits {
            bv.push(b);
        }
        let flat = bitvec_to_flat(&bv);
        assert_eq!(flat.len, bits.len() as u32);
        let view = flat.view();
        assert_eq!(view.len(), bits.len());
        for (i, &expected) in bits.iter().enumerate() {
            assert_eq!(view.get(i), expected, "mismatch at bit {}", i);
        }
    }

    #[test]
    fn test_bitvec_all_ones() {
        let mut bv: BitVec = BitVec::new();
        for _ in 0..17 {
            bv.push(true);
        }
        let flat = bitvec_to_flat(&bv);
        let view = flat.view();
        assert_eq!(view.len(), 17);
        for i in 0..17 {
            assert!(view.get(i), "bit {} should be true", i);
        }
    }

    #[test]
    fn test_bitvec_repeat_false() {
        let bv: BitVec = BitVec::repeat(false, 32);
        let flat = bitvec_to_flat(&bv);
        let view = flat.view();
        assert_eq!(view.len(), 32);
        for i in 0..32 {
            assert!(!view.get(i));
        }
    }

    // ── line_index ───────────────────────────────────────────────────────────

    #[test]
    fn test_line_index_round_trip() {
        let data = b"line0\nline1\nline2\n";
        let li = LineIndex::build(data);
        let archive = line_index_to_archive(&li);

        assert_eq!(archive.total, li.total_lines());
        assert_eq!(archive.sampled_offsets, li.sampled_offsets());

        let view = archive.view();
        assert_eq!(view.total_lines(), 3);
        assert_eq!(view.get_line(data, 0), Some(b"line0".as_slice()));
        assert_eq!(view.get_line(data, 1), Some(b"line1".as_slice()));
        assert_eq!(view.get_line(data, 2), Some(b"line2".as_slice()));
        assert_eq!(view.get_line(data, 3), None);
    }

    #[test]
    fn test_line_index_large() {
        let mut content = String::new();
        for i in 0..600 {
            content.push_str(&format!("line{}\n", i));
        }
        let data = content.as_bytes();
        let li = LineIndex::build(data);
        let archive = line_index_to_archive(&li);
        let view = archive.view();
        assert_eq!(view.total_lines(), 600);
        assert_eq!(view.get_line(data, 0), Some(b"line0".as_slice()));
        assert_eq!(view.get_line(data, 255), Some(b"line255".as_slice()));
        assert_eq!(view.get_line(data, 256), Some(b"line256".as_slice()));
        assert_eq!(view.get_line(data, 599), Some(b"line599".as_slice()));
    }
}
