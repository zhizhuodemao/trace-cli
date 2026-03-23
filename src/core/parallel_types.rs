//! Type definitions for parallel chunk scanning.
//!
//! These types are used by `chunk_scan`, `merge`, and `parallel` modules
//! to split the trace file into chunks, scan each independently, and merge results.

#![allow(dead_code)]

use bitvec::prelude::BitVec;
use rustc_hash::FxHashMap;
use smallvec::SmallVec;

use crate::index::line_index::LineIndex;
use crate::core::mem_access::MemAccessIndex;
use crate::core::reg_checkpoint::RegCheckpoints;
use crate::core::scanner::{CompactDeps, PairSplitDeps, RegLastDef};
use crate::core::types::RegId;

// === Cross-boundary unresolved items ===

/// A non-pair LOAD where ALL bytes had no local mem_last_def.
/// scan_chunk defers this entirely to fixup — no deps added.
pub struct UnresolvedLoad {
    pub line: u32,
    pub addr: u64,
    pub width: u8,
    pub load_value: Option<u64>,
    pub uses: SmallVec<[RegId; 4]>,
}

/// A non-pair LOAD where SOME bytes had local mem_last_def but others did not (mixed case).
/// pass-through is always false for mixed case. Reg deps already added by scan_chunk.
/// fixup supplements missing mem deps.
pub struct PartialUnresolvedLoad {
    pub line: u32,
    pub missing_addrs: SmallVec<[u64; 8]>,
}

/// A pair LOAD (LDP) where ALL memory deps are fully unresolved.
pub struct UnresolvedPairLoad {
    pub line: u32,
    pub addr: u64,
    pub elem_width: u8,
    pub base_reg: Option<RegId>,
    pub defs: SmallVec<[RegId; 3]>,
}

/// A pair LOAD where one half is locally resolved but the other is not.
pub struct PartialUnresolvedPairLoad {
    pub line: u32,
    pub addr: u64,
    pub elem_width: u8,
    pub half1_unresolved: bool,
    pub half2_unresolved: bool,
    pub base_reg: Option<RegId>,
    pub base_reg_unresolved: bool,
}

/// A register USE where reg_last_def was undefined (no prior DEF in this chunk).
pub struct UnresolvedRegUse {
    pub line: u32,
    pub reg: RegId,
}

// === CallTree event log ===

/// Events recorded during chunk scanning for later replay into CallTreeBuilder.
#[derive(Clone)]
pub enum CallTreeEvent {
    Call { seq: u32, target: u64 },
    Ret { seq: u32 },
    BlrPending { seq: u32, pc: u64 },
    LineAddr { seq: u32, addr: u64 },
    SetFuncName { entry_seq: u32, name: String },
    SetRootAddr { addr: u64 },
}

// === Gumtrace annotation event log ===

/// Events recorded during chunk scanning for later replay of Gumtrace annotations.
#[derive(Clone)]
pub enum GumtraceAnnotEvent {
    BranchInstr { seq: u32 },
    SpecialLine { seq: u32, special: SpecialLineData },
    OrphanLine { seq: u32 },
}

/// Parsed content of a Gumtrace special line.
#[derive(Clone)]
pub enum SpecialLineData {
    CallFunc {
        name: String,
        is_jni: bool,
        raw: String,
    },
    Arg {
        index: String,
        value: String,
        raw: String,
    },
    Ret {
        value: String,
        raw: String,
    },
    HexDump {
        raw: String,
    },
}

// === Per-chunk boundary state ===

/// Final scanner state at the end of a chunk, needed to resolve cross-chunk dependencies.
pub struct ChunkBoundaryState {
    pub final_reg_last_def: RegLastDef,
    pub final_mem_last_def: FxHashMap<u64, (u32, u64)>,
    pub final_last_cond_branch: Option<u32>,
    pub final_reg_values: [u64; RegId::COUNT],
    pub final_line_count: u32,
    pub final_parsed_count: u32,
    pub final_mem_op_count: u32,
}

// === Per-chunk scan result ===

/// Complete result of scanning a single chunk, before cross-chunk fixup.
pub struct ChunkResult {
    // Core data (using global line numbers)
    pub deps: CompactDeps,
    pub init_mem_loads: BitVec,
    pub pair_split: FxHashMap<u32, PairSplitDeps>,
    pub line_index: LineIndex,
    pub mem_access_index: MemAccessIndex,
    pub reg_checkpoints: RegCheckpoints,
    /// Write 操作记录 (addr, value, size, seq)，按 seq 顺序（扫描顺序）。
    /// 用于 merge 阶段精确构建字符串索引，避免遍历 MemAccessIndex HashMap。
    pub string_writes: Vec<(u64, u64, u8, u32)>,

    // Unresolved items
    pub unresolved_loads: Vec<UnresolvedLoad>,
    pub partial_unresolved_loads: Vec<PartialUnresolvedLoad>,
    pub unresolved_pair_loads: Vec<UnresolvedPairLoad>,
    pub partial_unresolved_pair_loads: Vec<PartialUnresolvedPairLoad>,
    pub unresolved_reg_uses: Vec<UnresolvedRegUse>,
    pub first_local_cond_branch: Option<u32>,
    /// Per-line: whether this line needs a control dep (non-pair, parsed, non-data_only)
    pub needs_control_dep: BitVec,

    // Event logs
    pub call_tree_events: Vec<CallTreeEvent>,
    pub gumtrace_annot_events: Vec<GumtraceAnnotEvent>,
    pub consumed_seqs: Vec<u32>,

    // Boundary state for next chunk's fixup
    pub boundary: ChunkBoundaryState,

    // Chunk metadata
    pub start_line: u32,
    pub end_line: u32,
    pub start_byte: usize,
    pub end_byte: usize,
}
