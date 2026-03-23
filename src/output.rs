use anyhow::{bail, Result};

use crate::core::slicer::bfs_slice;
use crate::core::types::parse_reg;
use crate::func_stats::compute_func_stats;
use crate::session::Session;

const MAX_LINES: usize = 50;

/// Extract the module name from the first instruction line.
/// Looks for `][module.so 0x...]` pattern in unidbg format:
/// `[07:17:13 488][libtiny.so 0x174250] ...`
fn extract_module_name(data: &[u8]) -> String {
    // Search the first few KB for the pattern "][" followed by module name
    let search_end = data.len().min(4096);
    let haystack = std::str::from_utf8(&data[..search_end]).unwrap_or("");
    // Find "][" which marks the boundary between timestamp and module sections
    if let Some(pos) = haystack.find("][") {
        let inner = &haystack[pos + 2..]; // skip "]["
        // Module name ends at space: "libtiny.so 0x..."
        if let Some(space) = inner.find(' ') {
            return inner[..space].to_string();
        }
    }
    "unknown".to_string()
}

pub fn print_overview(session: &Session) {
    let data: &[u8] = &session.mmap;
    let module_name = extract_module_name(data);
    println!("Trace: {}  {} lines  unidbg", module_name, session.total_lines);
    println!();

    let stats = compute_func_stats(&session.call_tree);
    let max_depth: u32 = 2;
    let mut printed = 0usize;
    let total_eligible = stats.iter().filter(|s| s.depth <= max_depth).count();

    for s in &stats {
        if s.depth > max_depth {
            continue;
        }
        if printed >= MAX_LINES {
            let remaining = total_eligible - printed;
            if remaining > 0 {
                println!("... {} more functions", remaining);
            }
            break;
        }

        let indent = "  ".repeat(s.depth as usize);
        let loop_info = s.children.iter()
            .filter(|(_, count)| *count > 1)
            .map(|(_, count)| format!("loop:{}", count))
            .collect::<Vec<_>>();
        let loop_str = if loop_info.is_empty() {
            String::new()
        } else {
            format!("  [{}]", loop_info.join(", "))
        };

        let addr_str = if s.func_addr != 0 {
            format!("0x{:x}", s.func_addr)
        } else {
            "root".to_string()
        };

        println!(
            "{}{}  {} insns  x{}{}",
            indent, addr_str, s.insn_count,
            s.children.len(),
            loop_str
        );
        printed += 1;
    }
}

pub fn print_lines(session: &Session, start: u32, end: u32) {
    let data: &[u8] = &session.mmap;
    let view = session.line_index_view();
    let total = end.saturating_sub(start) + 1;
    let show = total.min(MAX_LINES as u32);

    if total > MAX_LINES as u32 {
        println!("showing first {} of {} requested lines", MAX_LINES, total);
        println!();
    }

    for seq in start..start + show {
        if let Some(line_bytes) = view.get_line(data, seq) {
            let line = String::from_utf8_lossy(line_bytes);
            println!("[{}] {}", seq, line);
        }
    }
}

pub fn print_taint(session: &Session, spec: &str) -> Result<()> {
    // Parse spec: "x0@last" or "x0@5000"
    let parts: Vec<&str> = spec.splitn(2, '@').collect();
    if parts.len() != 2 {
        bail!("invalid spec '{}': expected format 'REG@POSITION' (e.g. x0@last, x0@5000)", spec);
    }

    let reg_name = parts[0];
    let position = parts[1];

    let reg_id = parse_reg(reg_name)
        .ok_or_else(|| anyhow::anyhow!("unknown register: {}", reg_name))?;

    // Resolve the starting line index
    let start_index = if position == "last" {
        // Use reg_last_def to find the last definition
        let raw = session.reg_last_def.get(&reg_id)
            .ok_or_else(|| anyhow::anyhow!("register {} has no definition in trace", reg_name))?;
        *raw
    } else {
        // Parse as a line number, use that directly
        let target_seq: u32 = position.parse()
            .map_err(|_| anyhow::anyhow!("invalid position '{}': expected 'last' or a line number", position))?;

        // The user wants to slice from reg at a specific line.
        // We need to find where reg was last defined at or before target_seq.
        // Scan backward using reg_last_def won't work since it only has the final state.
        // For simplicity, we just use target_seq as the start line directly.
        // The user presumably knows that the register is defined at that line.
        target_seq
    };

    let scan_view = session.scan_view();
    let marked = bfs_slice(&scan_view, &[start_index]);
    let total_marked = marked.count_ones();

    println!("Taint: {} @ line {}  ({} tainted lines / {} total)",
             reg_name, start_index & 0x1FFFFFFF, total_marked, session.total_lines);
    println!();

    let data: &[u8] = &session.mmap;
    let view = session.line_index_view();
    let mut printed = 0usize;

    for (i, is_set) in marked.iter().enumerate() {
        if !*is_set {
            continue;
        }
        if printed >= MAX_LINES {
            let remaining = total_marked - printed;
            println!("... {} more tainted lines ({}/{})", remaining, total_marked, session.total_lines);
            break;
        }
        if let Some(line_bytes) = view.get_line(data, i as u32) {
            let line = String::from_utf8_lossy(line_bytes);
            println!("[{}] {}", i, line);
        }
        printed += 1;
    }

    Ok(())
}
