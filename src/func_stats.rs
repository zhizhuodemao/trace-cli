use rustc_hash::FxHashMap;
use crate::core::call_tree::CallTree;

pub struct FuncStats {
    pub node_id: u32,
    pub func_addr: u64,
    pub entry_seq: u32,
    pub exit_seq: u32,
    pub insn_count: u32,
    pub depth: u32,
    pub children: Vec<(u64, u32)>,  // (addr, count) of direct children
}

pub fn compute_func_stats(call_tree: &CallTree) -> Vec<FuncStats> {
    // Compute depth for each node via BFS from root
    let mut depths: Vec<u32> = vec![0; call_tree.nodes.len()];
    let mut queue = std::collections::VecDeque::new();
    queue.push_back(0u32);
    while let Some(node_id) = queue.pop_front() {
        let node = &call_tree.nodes[node_id as usize];
        for &child_id in &node.children_ids {
            depths[child_id as usize] = depths[node_id as usize] + 1;
            queue.push_back(child_id);
        }
    }

    let mut stats = Vec::with_capacity(call_tree.nodes.len());

    for node in &call_tree.nodes {
        // Count children by function address
        let mut child_counts: FxHashMap<u64, u32> = FxHashMap::default();
        for &child_id in &node.children_ids {
            let child = &call_tree.nodes[child_id as usize];
            *child_counts.entry(child.func_addr).or_insert(0) += 1;
        }
        let mut children: Vec<(u64, u32)> = child_counts.into_iter().collect();
        children.sort_unstable_by_key(|(_, count)| std::cmp::Reverse(*count));

        let insn_count = if node.exit_seq >= node.entry_seq {
            node.exit_seq - node.entry_seq
        } else {
            0
        };

        stats.push(FuncStats {
            node_id: node.id,
            func_addr: node.func_addr,
            entry_seq: node.entry_seq,
            exit_seq: node.exit_seq,
            insn_count,
            depth: depths[node.id as usize],
            children,
        });
    }

    stats
}
