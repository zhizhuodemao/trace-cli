use std::sync::Arc;
use anyhow::Result;
use memmap2::Mmap;

use crate::core::call_tree::CallTree;
use crate::core::scanner::RegLastDef;
use crate::flat::archives::{CachedStore, Phase2Archive, ScanArchive};
use crate::flat::convert;
use crate::flat::line_index::LineIndexArchive;
use crate::flat::scan_view::ScanView;
use crate::flat::line_index::LineIndexView;
use crate::flat::mem_last_def::MemLastDefView;
use crate::flat::reg_checkpoints::RegCheckpointsView;
use crate::flat::mem_access::MemAccessView;
use crate::index::cache;

pub struct Session {
    pub mmap: Arc<Mmap>,
    pub file_path: String,
    pub total_lines: u32,
    pub call_tree: CallTree,
    pub phase2_store: CachedStore<Phase2Archive>,
    pub scan_store: CachedStore<ScanArchive>,
    pub lidx_store: CachedStore<LineIndexArchive>,
    pub reg_last_def: RegLastDef,
}

impl Session {
    pub fn open(path: &str) -> Result<Session> {
        let file = std::fs::File::open(path)?;
        let mmap = unsafe { Mmap::map(&file)? };
        let mmap = Arc::new(mmap);
        let data: &[u8] = &mmap;

        // Try loading all 3 caches
        let p2_cache = cache::load_phase2_cache(path, data);
        let scan_cache = cache::load_scan_cache(path, data);
        let lidx_cache = cache::load_lidx_cache(path, data);

        let (phase2_store, scan_store, lidx_store) = if let (Some(p2), Some(sc), Some(li)) =
            (p2_cache, scan_cache, lidx_cache)
        {
            eprintln!("[session] all caches hit");
            (
                CachedStore::<Phase2Archive>::Mapped(p2),
                CachedStore::<ScanArchive>::Mapped(sc),
                CachedStore::<LineIndexArchive>::Mapped(li),
            )
        } else {
            eprintln!("[session] cache miss, running scan...");
            let num_chunks = rayon::current_num_threads().max(1);
            let scan_result = crate::core::parallel::scan_unified_parallel(
                data,
                false,  // data_only
                false,  // no_prune
                false,  // skip_strings
                Some(Box::new(|pos, total| {
                    let pct = (pos as f64 / total as f64 * 100.0) as u32;
                    eprint!("\r[session] scanning... {}%", pct);
                })),
                num_chunks,
            )?;
            eprintln!("\r[session] scan complete: {} lines", scan_result.scan_state.line_count);

            // Compact mem_last_def before conversion
            let mut scan_state = scan_result.scan_state;
            scan_state.compact();

            // Build archives
            let phase2_archive = Phase2Archive {
                mem_accesses: convert::mem_access_to_flat(&scan_result.phase2.mem_accesses),
                reg_checkpoints: convert::reg_checkpoints_to_flat(&scan_result.phase2.reg_checkpoints),
                call_tree: scan_result.phase2.call_tree,
            };
            let scan_archive = ScanArchive {
                deps: convert::deps_to_flat(&scan_state.deps),
                mem_last_def: convert::mem_last_def_to_flat(&scan_state.mem_last_def),
                pair_split: convert::pair_split_to_flat(&scan_state.pair_split),
                init_mem_loads: convert::bitvec_to_flat(&scan_state.init_mem_loads),
                reg_last_def_inner: scan_state.reg_last_def.inner().to_vec(),
                line_count: scan_state.line_count,
                parsed_count: scan_state.parsed_count,
                mem_op_count: scan_state.mem_op_count,
            };
            let lidx_archive = convert::line_index_to_archive(&scan_result.line_index);

            // Save caches to disk
            let p2_bytes = phase2_archive.to_sections();
            cache::save_sections_raw(path, data, ".p2.cache", &p2_bytes);
            let scan_bytes = scan_archive.to_sections();
            cache::save_sections_raw(path, data, ".scan.cache", &scan_bytes);
            let lidx_bytes = lidx_archive.to_sections();
            cache::save_sections_raw(path, data, ".lidx.cache", &lidx_bytes);

            (
                CachedStore::Owned(phase2_archive),
                CachedStore::Owned(scan_archive),
                CachedStore::Owned(lidx_archive),
            )
        };

        let call_tree = phase2_store.deserialize_call_tree();
        let total_lines = lidx_store.total_lines();
        let reg_last_def = scan_store.deserialize_reg_last_def();

        Ok(Session {
            mmap,
            file_path: path.to_string(),
            total_lines,
            call_tree,
            phase2_store,
            scan_store,
            lidx_store,
            reg_last_def,
        })
    }

    pub fn line_index_view(&self) -> LineIndexView<'_> {
        self.lidx_store.view()
    }

    pub fn scan_view(&self) -> ScanView<'_> {
        self.scan_store.scan_view()
    }

    pub fn mem_last_def_view(&self) -> MemLastDefView<'_> {
        self.scan_store.mem_last_def_view()
    }

    pub fn reg_checkpoints_view(&self) -> RegCheckpointsView<'_> {
        self.phase2_store.reg_checkpoints_view()
    }

    pub fn mem_accesses_view(&self) -> MemAccessView<'_> {
        self.phase2_store.mem_accesses_view()
    }
}
