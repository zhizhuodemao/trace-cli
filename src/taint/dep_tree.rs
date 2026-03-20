use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};

use crate::flat::line_index::LineIndexView;
use crate::flat::scan_view::ScanView;
use crate::taint::def_use::determine_def_use;
use crate::taint::gumtrace_parser;
use crate::taint::insn_class;
use crate::taint::parser;
use crate::taint::scanner::{CONTROL_DEP_BIT, LINE_MASK, PAIR_HALF2_BIT, PAIR_SHARED_BIT};
use crate::taint::types::TraceFormat;
use rustc_hash::FxHashMap;

/// 扁平 DAG：节点数组 + 边列表，无递归嵌套
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DependencyGraph {
    pub nodes: Vec<NodeInfo>,
    pub edges: Vec<[u32; 2]>,   // [parent_seq, child_seq]
    pub root_seq: u32,
    pub total_reachable: u32,   // BFS 可达的总节点数
    pub truncated: bool,        // 是否因超出 max_nodes 而截断
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeInfo {
    pub seq: u32,
    pub expression: String,
    pub asm: String,           // 新增：原始汇编文本
    pub operation: String,
    pub is_leaf: bool,
    pub value: Option<String>,
    pub depth: u32, // BFS 最短深度
}

/// 构建扁平依赖图：BFS 遍历依赖关系，输出去重的节点数组和边列表。
/// `max_nodes` 限制收集的节点数量，超出后仅计数不再收集。
pub fn build_graph(view: &ScanView, start_index: u32, data_only: bool, max_nodes: u32) -> DependencyGraph {
    let n = view.line_count as usize;
    let mut visited = bitvec::prelude::bitvec![0; n];
    let mut pair_visited: FxHashMap<u32, u8> = FxHashMap::default();
    let mut queue: VecDeque<u32> = VecDeque::new();

    // BFS 产出：节点集合（保留发现顺序）+ 去重边列表
    let mut node_seqs: Vec<u32> = Vec::new();
    let mut node_set: HashSet<u32> = HashSet::new();
    let mut edges: Vec<[u32; 2]> = Vec::new();
    let mut edge_set: HashSet<u64> = HashSet::new();
    let mut depth_map: HashMap<u32, u32> = HashMap::new();
    let mut children_exist: HashSet<u32> = HashSet::new();
    let mut collecting = true; // 是否仍在收集节点（未超限）

    let root_line = start_index & LINE_MASK;
    if (root_line as usize) >= n {
        return DependencyGraph {
            nodes: vec![],
            edges: vec![],
            root_seq: root_line,
            total_reachable: 0,
            truncated: false,
        };
    }

    visited.set(root_line as usize, true);
    queue.push_back(start_index);
    node_seqs.push(root_line);
    node_set.insert(root_line);
    depth_map.insert(root_line, 0);
    let mut total_reachable: u32 = 1;

    while let Some(raw) = queue.pop_front() {
        let parent_line = raw & LINE_MASK;
        let parent_depth = if collecting { depth_map.get(&parent_line).copied().unwrap_or(0) } else { 0 };
        let deps = collect_deps(raw, view, data_only);

        for dep_raw in deps {
            let dep_line = dep_raw & LINE_MASK;
            if (dep_line as usize) >= n {
                continue;
            }

            // 收集阶段：记录边（去重），仅对已收集的节点间的边
            if collecting && node_set.contains(&parent_line) {
                let edge_key = ((parent_line as u64) << 32) | (dep_line as u64);
                if edge_set.insert(edge_key) {
                    // 只保留两端都在收集范围内的边（dep_line 可能超限）
                    if node_set.contains(&dep_line) || total_reachable < max_nodes {
                        edges.push([parent_line, dep_line]);
                        children_exist.insert(parent_line);
                    }
                }
            }

            // BFS 入队（只对首次访问的节点入队）
            if view.pair_split.contains_key(&dep_line) {
                let visit_bit = if (dep_raw & PAIR_SHARED_BIT) != 0 {
                    4u8
                } else if (dep_raw & PAIR_HALF2_BIT) != 0 {
                    2u8
                } else {
                    1u8
                };
                let v = pair_visited.entry(dep_line).or_insert(0);
                if *v & visit_bit != 0 {
                    continue;
                }
                *v |= visit_bit;
            } else if visited[dep_line as usize] {
                continue;
            }

            visited.set(dep_line as usize, true);
            total_reachable += 1;

            if collecting {
                if node_set.insert(dep_line) {
                    node_seqs.push(dep_line);
                }
                depth_map.insert(dep_line, parent_depth + 1);
                // 检查是否达到上限
                if node_seqs.len() as u32 >= max_nodes {
                    collecting = false;
                    // 清理收集阶段的数据结构，释放内存
                    node_set.clear();
                    edge_set.clear();
                    depth_map.shrink_to_fit();
                }
            }

            queue.push_back(dep_raw);
        }
    }

    // 重建 node_set 用于 is_leaf 判断
    let node_set_final: HashSet<u32> = node_seqs.iter().copied().collect();
    // 过滤边：只保留两端都在节点集内的
    edges.retain(|[p, c]| node_set_final.contains(p) && node_set_final.contains(c));

    let nodes: Vec<NodeInfo> = node_seqs
        .iter()
        .map(|&seq| NodeInfo {
            seq,
            expression: String::new(),
            asm: String::new(),
            operation: String::new(),
            is_leaf: !children_exist.contains(&seq),
            value: None,
            depth: depth_map.get(&seq).copied().unwrap_or(0),
        })
        .collect();

    let truncated = total_reachable > nodes.len() as u32;

    DependencyGraph {
        nodes,
        edges,
        root_seq: root_line,
        total_reachable,
        truncated,
    }
}

/// 填充所有节点的 expression / operation / value 字段
pub fn populate_graph_info(
    graph: &mut DependencyGraph,
    mmap: &[u8],
    line_index: &LineIndexView,
    format: TraceFormat,
) {
    for node in &mut graph.nodes {
        fill_node_info(node, mmap, line_index, format);
    }
}

fn fill_node_info(
    node: &mut NodeInfo,
    mmap: &[u8],
    line_index: &LineIndexView,
    format: TraceFormat,
) {
    if let Some(raw_line) = line_index.get_line(mmap, node.seq) {
        if let Ok(line_str) = std::str::from_utf8(raw_line) {
            let parsed = match format {
                TraceFormat::Unidbg => parser::parse_line(line_str),
                TraceFormat::Gumtrace => gumtrace_parser::parse_line_gumtrace(line_str),
            };
            if let Some(ref p) = parsed {
                let cls = insn_class::classify_and_refine(p);
                let (defs, uses) = determine_def_use(cls, p);
                node.operation = p.mnemonic.to_string();

                let def_str = defs
                    .iter()
                    .map(|r| format!("{:?}", r))
                    .collect::<Vec<_>>()
                    .join(", ");
                let use_str = uses
                    .iter()
                    .map(|r| format!("{:?}", r))
                    .collect::<Vec<_>>()
                    .join(", ");
                let changes = extract_changes(line_str);

                if p.mem_op.is_some() {
                    let mem = p.mem_op.as_ref().unwrap();
                    if mem.is_write {
                        node.expression = format!("mem[0x{:x}] = {}", mem.abs, use_str);
                    } else {
                        node.expression = format!("{} = mem[0x{:x}]", def_str, mem.abs);
                    }
                } else if !def_str.is_empty() {
                    node.expression = format!("{} = {} {}", def_str, p.mnemonic, use_str);
                } else {
                    node.expression = format!("{} {}", p.mnemonic, use_str);
                }

                node.asm = extract_asm(line_str, format);

                if node.is_leaf && !changes.is_empty() {
                    node.value = Some(changes);
                }
            } else {
                node.expression = line_str.trim().to_string();
                node.asm = line_str.trim().to_string();
                node.operation = "unknown".to_string();
            }
        }
    }
}

fn collect_deps(raw: u32, view: &ScanView, data_only: bool) -> Vec<u32> {
    let line = raw & LINE_MASK;
    let mut deps = Vec::new();

    if let Some(split) = view.pair_split.get(&line) {
        if (raw & PAIR_SHARED_BIT) != 0 {
            for &dep in split.shared {
                if data_only && (dep & CONTROL_DEP_BIT) != 0 {
                    continue;
                }
                deps.push(dep);
            }
        } else {
            for &dep in split.shared {
                if data_only && (dep & CONTROL_DEP_BIT) != 0 {
                    continue;
                }
                deps.push(dep);
            }
            let half_deps = if (raw & PAIR_HALF2_BIT) != 0 {
                split.half2_deps
            } else {
                split.half1_deps
            };
            for &dep in half_deps {
                deps.push(dep);
            }
        }
    } else {
        for &dep in view
            .deps
            .row(line as usize)
            .iter()
            .chain(view.deps.patch_row(line as usize).iter())
        {
            if data_only && (dep & CONTROL_DEP_BIT) != 0 {
                continue;
            }
            deps.push(dep);
        }
    }

    deps
}

/// 从 trace 原始行中提取汇编文本（mnemonic + operands）。
fn extract_asm(line_str: &str, format: TraceFormat) -> String {
    match format {
        TraceFormat::Unidbg => {
            // Unidbg 格式: ... "mnemonic operands" ... => ...
            // 提取双引号之间的内容
            if let Some(start) = line_str.find('"') {
                if let Some(end) = line_str[start + 1..].find('"') {
                    return line_str[start + 1..start + 1 + end].trim().to_string();
                }
            }
            String::new()
        }
        TraceFormat::Gumtrace => {
            // Gumtrace 格式: addr | mnemonic operands | ...
            // 提取第一个 '|' 之后、第二个 '|' 之前的内容
            let parts: Vec<&str> = line_str.splitn(3, '|').collect();
            if parts.len() >= 2 {
                return parts[1].trim().to_string();
            }
            String::new()
        }
    }
}

fn extract_changes(line: &str) -> String {
    if let Some(pos) = line.rfind("=> ") {
        line[pos + 3..].trim().to_string()
    } else {
        String::new()
    }
}
