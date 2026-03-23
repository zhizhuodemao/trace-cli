use crate::core::call_tree::CallTree;
use crate::core::scanner::RegLastDef;
use crate::core::types::RegId;
use std::sync::Arc;
use memmap2::Mmap;

use super::cache_format::{SectionWriter, SectionReader};
use super::mem_access::{FlatMemAccess, MemAccessView};
use super::reg_checkpoints::{FlatRegCheckpoints, RegCheckpointsView};
use super::deps::{FlatDeps, DepsView};
use super::mem_last_def::{FlatMemLastDef, MemLastDefView};
use super::pair_split::{FlatPairSplit, PairSplitView};
use super::bitvec::{FlatBitVec, BitView};
use super::line_index::{LineIndexArchive, LineIndexView};
use super::scan_view::ScanView;

pub const HEADER_LEN: usize = 64;

// ── Phase2Archive ────────────────────────────────────────────────────────────

pub struct Phase2Archive {
    pub mem_accesses: FlatMemAccess,
    pub reg_checkpoints: FlatRegCheckpoints,
    pub call_tree: CallTree,
}

impl Phase2Archive {
    /// Serialize to section-based binary format.
    pub fn to_sections(&self) -> Vec<u8> {
        let mut w = SectionWriter::new();
        // MemAccess: sections 0-2
        w.write_slice(&self.mem_accesses.addrs);      // 0
        w.write_slice(&self.mem_accesses.offsets);     // 1
        w.write_slice(&self.mem_accesses.records);     // 2
        // RegCheckpoints: sections 3-5
        w.write_u32(self.reg_checkpoints.interval);    // 3
        w.write_u32(self.reg_checkpoints.count);       // 4
        w.write_slice(&self.reg_checkpoints.data);     // 5
        // CallTree: section 6 (bincode, eagerly deserialized on load)
        let ct_bytes = bincode::serialize(&self.call_tree).unwrap();
        w.write_bytes(&ct_bytes);                      // 6
        w.finish()
    }

    /// Reconstruct views from mmap'd section data.
    /// `data` = &mmap[HEADER_LEN..] (after 64-byte cache header)
    pub fn views_from_sections(data: &[u8]) -> Option<Phase2Views<'_>> {
        let r = SectionReader::new(data)?;
        if r.num_sections() < 7 { return None; }
        Some(Phase2Views {
            mem_accesses: MemAccessView::from_raw(
                r.slice(0), r.slice(1), r.slice(2),
            ),
            reg_checkpoints: RegCheckpointsView::from_raw(
                r.u32_val(3), r.u32_val(4), r.slice(5),
            ),
            call_tree_bytes: r.bytes(6),
        })
    }
}

pub struct Phase2Views<'a> {
    pub mem_accesses: MemAccessView<'a>,
    pub reg_checkpoints: RegCheckpointsView<'a>,
    pub call_tree_bytes: &'a [u8], // bincode bytes, deserialize on demand
}

// ── ScanArchive ──────────────────────────────────────────────────────────────

pub struct ScanArchive {
    pub deps: FlatDeps,
    pub mem_last_def: FlatMemLastDef,
    pub pair_split: FlatPairSplit,
    pub init_mem_loads: FlatBitVec,
    pub reg_last_def_inner: Vec<u32>, // [u32; 98] serialized as Vec
    pub line_count: u32,
    pub parsed_count: u32,
    pub mem_op_count: u32,
}

impl ScanArchive {
    pub fn to_sections(&self) -> Vec<u8> {
        let mut w = SectionWriter::new();
        // FlatDeps: sections 0-7
        w.write_slice(&self.deps.chunk_start_lines);     // 0
        w.write_slice(&self.deps.chunk_offsets_start);    // 1
        w.write_slice(&self.deps.chunk_data_start);       // 2
        w.write_slice(&self.deps.all_offsets);             // 3
        w.write_slice(&self.deps.all_data);                // 4
        w.write_slice(&self.deps.patch_lines);             // 5
        w.write_slice(&self.deps.patch_offsets);            // 6
        w.write_slice(&self.deps.patch_data);               // 7
        // FlatMemLastDef: sections 8-10
        w.write_slice(&self.mem_last_def.addrs);           // 8
        w.write_slice(&self.mem_last_def.lines);           // 9
        w.write_slice(&self.mem_last_def.values);          // 10
        // FlatPairSplit: sections 11-13
        w.write_slice(&self.pair_split.keys);              // 11
        w.write_slice(&self.pair_split.seg_offsets);       // 12
        w.write_slice(&self.pair_split.data);              // 13
        // FlatBitVec: sections 14-15
        w.write_slice(&self.init_mem_loads.data);          // 14
        w.write_u32(self.init_mem_loads.len);              // 15
        // Metadata: sections 16-19
        w.write_slice(&self.reg_last_def_inner);           // 16
        w.write_u32(self.line_count);                      // 17
        w.write_u32(self.parsed_count);                    // 18
        w.write_u32(self.mem_op_count);                    // 19
        w.finish()
    }

    pub fn views_from_sections(data: &[u8]) -> Option<ScanViews<'_>> {
        let r = SectionReader::new(data)?;
        if r.num_sections() < 20 { return None; }
        Some(ScanViews {
            deps: DepsView::from_raw(
                r.slice(0), r.slice(1), r.slice(2),
                r.slice(3), r.slice(4),
                r.slice(5), r.slice(6), r.slice(7),
            ),
            mem_last_def: MemLastDefView::from_raw(
                r.slice(8), r.slice(9), r.slice(10),
            ),
            pair_split: PairSplitView::from_raw(
                r.slice(11), r.slice(12), r.slice(13),
            ),
            init_mem_loads: BitView::from_raw(
                r.slice(14), r.u32_val(15),
            ),
            reg_last_def_inner: r.slice(16),
            line_count: r.u32_val(17),
            parsed_count: r.u32_val(18),
            mem_op_count: r.u32_val(19),
        })
    }
}

#[allow(dead_code)]
pub struct ScanViews<'a> {
    pub deps: DepsView<'a>,
    pub mem_last_def: MemLastDefView<'a>,
    pub pair_split: PairSplitView<'a>,
    pub init_mem_loads: BitView<'a>,
    pub reg_last_def_inner: &'a [u32],
    pub line_count: u32,
    pub parsed_count: u32,
    pub mem_op_count: u32,
}

// ── LineIndexArchive sections ────────────────────────────────────────────────

impl LineIndexArchive {
    pub fn to_sections(&self) -> Vec<u8> {
        let mut w = SectionWriter::new();
        w.write_slice(&self.sampled_offsets);  // 0
        w.write_u32(self.total);               // 1
        w.finish()
    }

    pub fn views_from_sections(data: &[u8]) -> Option<LineIndexView<'_>> {
        let r = SectionReader::new(data)?;
        if r.num_sections() < 2 { return None; }
        Some(LineIndexView::from_raw(
            r.slice(0), r.u32_val(1),
        ))
    }
}

// ── CachedStore ──────────────────────────────────────────────────────────────

pub enum CachedStore<A> {
    Owned(A),
    Mapped(Arc<Mmap>),
}

// ── CachedStore<Phase2Archive> ───────────────────────────────────────────────

impl CachedStore<Phase2Archive> {
    pub fn mem_accesses_view(&self) -> MemAccessView<'_> {
        match self {
            Self::Owned(a) => a.mem_accesses.view(),
            Self::Mapped(mmap) => {
                let views = Phase2Archive::views_from_sections(&mmap[HEADER_LEN..]).unwrap();
                views.mem_accesses
            }
        }
    }

    pub fn reg_checkpoints_view(&self) -> RegCheckpointsView<'_> {
        match self {
            Self::Owned(a) => a.reg_checkpoints.view(),
            Self::Mapped(mmap) => {
                let views = Phase2Archive::views_from_sections(&mmap[HEADER_LEN..]).unwrap();
                views.reg_checkpoints
            }
        }
    }

    pub fn deserialize_call_tree(&self) -> CallTree {
        match self {
            Self::Owned(a) => a.call_tree.clone(),
            Self::Mapped(mmap) => {
                let views = Phase2Archive::views_from_sections(&mmap[HEADER_LEN..]).unwrap();
                bincode::deserialize(views.call_tree_bytes)
                    .expect("failed to deserialize CallTree from cache")
            }
        }
    }
}

// ── CachedStore<ScanArchive> ─────────────────────────────────────────────────

impl CachedStore<ScanArchive> {
    pub fn deps_view(&self) -> DepsView<'_> {
        match self {
            Self::Owned(a) => a.deps.view(),
            Self::Mapped(mmap) => {
                let views = ScanArchive::views_from_sections(&mmap[HEADER_LEN..]).unwrap();
                views.deps
            }
        }
    }

    pub fn mem_last_def_view(&self) -> MemLastDefView<'_> {
        match self {
            Self::Owned(a) => a.mem_last_def.view(),
            Self::Mapped(mmap) => {
                let views = ScanArchive::views_from_sections(&mmap[HEADER_LEN..]).unwrap();
                views.mem_last_def
            }
        }
    }

    pub fn pair_split_view(&self) -> PairSplitView<'_> {
        match self {
            Self::Owned(a) => a.pair_split.view(),
            Self::Mapped(mmap) => {
                let views = ScanArchive::views_from_sections(&mmap[HEADER_LEN..]).unwrap();
                views.pair_split
            }
        }
    }

    pub fn init_mem_loads_view(&self) -> BitView<'_> {
        match self {
            Self::Owned(a) => a.init_mem_loads.view(),
            Self::Mapped(mmap) => {
                let views = ScanArchive::views_from_sections(&mmap[HEADER_LEN..]).unwrap();
                views.init_mem_loads
            }
        }
    }

    pub fn line_count(&self) -> u32 {
        match self {
            Self::Owned(a) => a.line_count,
            Self::Mapped(mmap) => {
                let views = ScanArchive::views_from_sections(&mmap[HEADER_LEN..]).unwrap();
                views.line_count
            }
        }
    }

    pub fn reg_last_def_inner(&self) -> &[u32] {
        match self {
            Self::Owned(a) => &a.reg_last_def_inner,
            Self::Mapped(mmap) => {
                let views = ScanArchive::views_from_sections(&mmap[HEADER_LEN..]).unwrap();
                views.reg_last_def_inner
            }
        }
    }

    pub fn deserialize_reg_last_def(&self) -> RegLastDef {
        let inner = self.reg_last_def_inner();
        let mut rld = RegLastDef::new();
        for (i, &v) in inner.iter().enumerate().take(RegId::COUNT) {
            if v != u32::MAX {
                rld.insert(RegId(i as u8), v);
            }
        }
        rld
    }

    pub fn scan_view(&self) -> ScanView<'_> {
        ScanView {
            deps: self.deps_view(),
            pair_split: self.pair_split_view(),
            line_count: self.line_count(),
        }
    }
}

// ── CachedStore<LineIndexArchive> ────────────────────────────────────────────

impl CachedStore<LineIndexArchive> {
    pub fn total_lines(&self) -> u32 {
        self.view().total_lines()
    }

    pub fn view(&self) -> LineIndexView<'_> {
        match self {
            Self::Owned(a) => a.view(),
            Self::Mapped(mmap) => {
                LineIndexArchive::views_from_sections(&mmap[HEADER_LEN..]).unwrap()
            }
        }
    }
}
