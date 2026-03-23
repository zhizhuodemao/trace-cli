use memchr::memchr;
use memchr::memmem;
use smallvec::SmallVec;

use super::types::*;

/// 从行中提取引号内的反汇编文本，同时返回第二个引号的位置。
/// 返回 (disasm_str, quote2_position) 以便后续搜索从 quote2 之后继续。
fn find_disasm_with_pos(line: &[u8]) -> Option<(&str, usize)> {
    // unidbg 格式前 ~40 字节是固定格式（时间戳+模块名+地址），引号不会出现在这里
    let skip = 40.min(line.len());
    let q1 = memchr(b'"', &line[skip..])? + skip;
    let q2 = memchr(b'"', &line[q1 + 1..])? + q1 + 1;
    // SAFETY: trace lines are ASCII (ARM64 disassembly text)
    let s = unsafe { std::str::from_utf8_unchecked(&line[q1 + 1..q2]) };
    Some((s, q2))
}

/// 手动解析十六进制字节序列到 u64。
pub(crate) fn parse_hex_u64(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    let mut result: u64 = 0;
    for &b in bytes {
        let digit = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => return None,
        };
        result = result.checked_mul(16)?.checked_add(digit as u64)?;
    }
    Some(result)
}

/// 手动解析十六进制字节序列到 u128（用于 128-bit SIMD q 寄存器值）。
pub(crate) fn parse_hex_u128(bytes: &[u8]) -> Option<u128> {
    if bytes.is_empty() {
        return None;
    }
    let mut val: u128 = 0;
    for &b in bytes {
        let digit = match b {
            b'0'..=b'9' => (b - b'0') as u128,
            b'a'..=b'f' => (b - b'a' + 10) as u128,
            b'A'..=b'F' => (b - b'A' + 10) as u128,
            _ => return None,
        };
        val = val.checked_mul(16)?.checked_add(digit)?;
    }
    Some(val)
}

/// 从 `line[from..]` 中提取 mem[READ/WRITE] abs=0xADDR。
/// `from` 允许调用者跳过行首已扫描的部分，避免重复搜索。
fn find_mem_op_raw(line: &[u8], from: usize) -> Option<(bool, u64)> {
    let search = &line[from..];
    let rel_pos = memmem::find(search, b"mem[")?;
    let pos = from + rel_pos;
    let is_write = *line.get(pos + 4)? == b'W';
    let abs_marker = memmem::find(&line[pos..], b"abs=0x")?;
    let val_start = pos + abs_marker + 6;
    let val_end = line[val_start..]
        .iter()
        .position(|b| !b.is_ascii_hexdigit())
        .map(|p| val_start + p)
        .unwrap_or(line.len());
    let addr = parse_hex_u64(&line[val_start..val_end])?;
    Some((is_write, addr))
}

/// Parse a trace line (lightweight mode for scan — skips arrow register extraction).
///
/// Returns `None` for lines that don't match the expected trace format
/// (empty lines, log lines without disassembly, etc.).
pub fn parse_line(raw: &str) -> Option<ParsedLine> {
    parse_line_inner(raw, false)
}

/// Parse a trace line (full mode for validate — includes arrow register extraction).
#[allow(dead_code)]
pub fn parse_line_full(raw: &str) -> Option<ParsedLine> {
    parse_line_inner(raw, true)
}

fn parse_line_inner(raw: &str, extract_regs: bool) -> Option<ParsedLine> {
    let bytes = raw.as_bytes();

    // 1. Extract disassembly inside quotes + cursor position after quote2
    let (disasm, q2) = find_disasm_with_pos(bytes)?;

    // 2. Split mnemonic and operand text
    let (mnemonic, operand_text) = match disasm.find(' ') {
        Some(pos) => (&disasm[..pos], disasm[pos + 1..].trim()),
        None => (disasm, ""),
    };

    // Reject empty mnemonic (e.g., from `""` in trace)
    if mnemonic.is_empty() {
        return None;
    }

    // 3. Parse operand list (searches only within operand_text — no full-line scan)
    let mut result_line = ParsedLine::default();
    let raw_first_reg_prefix = parse_operands_into(operand_text, &mut result_line);

    // 4. Find arrow — search only from quote2 onward (not from line start)
    let tail = &bytes[q2..];
    let arrow_rel = memmem::find(tail, b" => ");
    let has_arrow = arrow_rel.is_some();

    let (pre_arrow_regs, post_arrow_regs);
    if extract_regs {
        if let Some(rel) = arrow_rel {
            let arrow_abs = q2 + rel;
            pre_arrow_regs = Some(Box::new(extract_reg_values(&raw[..arrow_abs])));
            post_arrow_regs = Some(Box::new(extract_reg_values(&raw[arrow_abs + 4..])));
        } else {
            pre_arrow_regs = Some(Box::new(extract_reg_values(raw)));
            post_arrow_regs = Some(Box::new(SmallVec::new()));
        }
    } else {
        pre_arrow_regs = None;
        post_arrow_regs = None;
    }

    // 5. Parse mem[READ/WRITE] — search from quote2 onward (mem always appears after disasm)
    let mem_op = find_mem_op_raw(bytes, q2).map(|(is_write, abs)| {
        let mut elem_width = determine_elem_width(mnemonic, raw_first_reg_prefix);
        // 5a. 修正 elem_width：lane load 用 lane 元素宽度，SIMD 向量用排列说明符宽度
        if let (Some(_), Some(lew)) = (result_line.lane_index, result_line.lane_elem_width) {
            elem_width = lew;
        } else if matches!(mnemonic, "ld1" | "ld2" | "ld3" | "ld4" | "st1" | "st2" | "st3" | "st4") {
            if let Some(arr_width) = simd_arrangement_total_width(operand_text) {
                elem_width = arr_width;
            }
        }
        // 寄存器值搜索起始位置
        let search_start = if is_write {
            Some(q2)
        } else {
            arrow_rel.map(|rel| q2 + rel + 4)
        };
        // 5b. Extract first register value
        let (value, value_lo, value_hi) = if elem_width <= 8 {
            let v = first_data_reg_name(operand_text).and_then(|reg_name| {
                let ss = search_start?;
                if is_simd_reg_name(reg_name) {
                    // SIMD 寄存器：先尝试 q 前缀再回退原名，解析 u128 后提取位域
                    let full = find_simd_reg_u128(bytes, reg_name, ss)?;
                    Some(extract_simd_lane_value(full, elem_width, result_line.lane_index))
                } else {
                    let raw_val = find_reg_value(bytes, reg_name.as_bytes(), ss)?;
                    let mask = if elem_width >= 8 {
                        u64::MAX
                    } else {
                        (1u64 << (elem_width as u32 * 8)) - 1
                    };
                    Some(raw_val & mask)
                }
            });
            (v, None, None)
        } else if elem_width == 16 {
            // 128-bit SIMD: 用 u128 解析后拆为 low/high 两个 u64
            let v128 = first_data_reg_name(operand_text).and_then(|reg_name| {
                find_simd_reg_u128(bytes, reg_name, search_start?)
            });
            match v128 {
                Some(val) => (None, Some(val as u64), Some((val >> 64) as u64)),
                None => (None, None, None),
            }
        } else {
            (None, None, None)
        };
        // Pair / multi-register SIMD：提取第二个寄存器的值
        let (value2, value2_lo, value2_hi) = if is_pair_mnemonic(mnemonic)
            || is_simd_multi_reg(mnemonic, operand_text)
        {
            if elem_width <= 8 {
                let v2 = second_data_reg_name(operand_text).and_then(|reg_name| {
                    let ss = search_start?;
                    if is_simd_reg_name(reg_name) {
                        let full = find_simd_reg_u128(bytes, reg_name, ss)?;
                        Some(extract_simd_lane_value(full, elem_width, None))
                    } else {
                        let raw_val = find_reg_value(bytes, reg_name.as_bytes(), ss)?;
                        let mask = if elem_width >= 8 { u64::MAX } else { (1u64 << (elem_width as u32 * 8)) - 1 };
                        Some(raw_val & mask)
                    }
                });
                (v2, None, None)
            } else if elem_width == 16 {
                let v128 = second_data_reg_name(operand_text).and_then(|reg_name| {
                    find_simd_reg_u128(bytes, reg_name, search_start?)
                });
                match v128 {
                    Some(val) => (None, Some(val as u64), Some((val >> 64) as u64)),
                    None => (None, None, None),
                }
            } else {
                (None, None, None)
            }
        } else {
            (None, None, None)
        };
        MemOp {
            is_write,
            abs,
            elem_width,
            value,
            value2,
            value_lo,
            value_hi,
            value2_lo,
            value2_hi,
        }
    });

    // 6. Detect writeback (searches only operand_text — no full-line scan)
    let op_bytes = operand_text.as_bytes();
    let writeback = memchr(b'!', op_bytes).is_some() || memmem::find(op_bytes, b"], #").is_some();

    result_line.mnemonic = Mnemonic::new(mnemonic);
    result_line.mem_op = mem_op;
    result_line.has_arrow = has_arrow;
    result_line.arrow_pos = arrow_rel.map(|rel| q2 + rel);
    result_line.writeback = writeback;
    result_line.pre_arrow_regs = pre_arrow_regs;
    result_line.post_arrow_regs = post_arrow_regs;

    Some(result_line)
}

/// 从文本中提取所有 `name=0xHEX` 寄存器值对（手写替换 REG_VAL_RE）。
///
/// 扫描 `=0x` 模式，向左提取寄存器名，向右提取十六进制值。
/// 128-bit SIMD 值溢出 u64 时截断为 0。
pub(crate) fn extract_reg_values(text: &str) -> SmallVec<[(RegId, u64); 4]> {
    let bytes = text.as_bytes();
    let mut result = SmallVec::new();
    let mut pos = 0;

    while pos + 3 <= bytes.len() {
        // 查找 "=0x" 模式
        let eq_pos = match memmem::find(&bytes[pos..], b"=0x") {
            Some(p) => pos + p,
            None => break,
        };

        // 向左提取寄存器名：连续的 ASCII 字母+数字
        let name_start = bytes[..eq_pos]
            .iter()
            .rposition(|b| !b.is_ascii_alphanumeric())
            .map(|p| p + 1)
            .unwrap_or(0);

        // 名字至少 2 字符（如 "x0"），且首字符为小写字母
        let name_bytes = &bytes[name_start..eq_pos];
        let valid_name = name_bytes.len() >= 2 && name_bytes[0].is_ascii_lowercase();

        // 向右提取十六进制值
        let val_start = eq_pos + 3; // 跳过 "=0x"
        let val_end = bytes[val_start..]
            .iter()
            .position(|b| !b.is_ascii_hexdigit())
            .map(|p| val_start + p)
            .unwrap_or(bytes.len());

        if valid_name {
            // SAFETY: name_bytes are already validated as ASCII alphanumeric above
            let name_str = unsafe { std::str::from_utf8_unchecked(name_bytes) };
            if let Some(reg) = parse_reg(name_str) {
                let val = parse_hex_u64(&bytes[val_start..val_end]).unwrap_or(0);
                result.push((reg, val));
            }
        }

        pos = val_end.max(eq_pos + 3); // 至少前进到 "=0x" 之后
    }

    result
}

/// Parse operand text (comma-separated), writing results directly into `out`.
///
/// Returns the first operand's raw register prefix byte (needed for memory access
/// width before register normalization, e.g., 'w' -> 4 bytes, 'x' -> 8 bytes).
///
/// Also populates `out.operands`, `out.base_reg`, and `out.lane_index`.
pub(crate) fn parse_operands_into(text: &str, out: &mut ParsedLine) -> Option<u8> {
    let mut first_reg_prefix: Option<u8> = None;

    if text.is_empty() {
        return first_reg_prefix;
    }

    let tokens = split_operands(text);

    for (i, token) in tokens.iter().enumerate() {
        let token = token.trim();

        // Strip curly braces (SIMD register list markers), zero allocation
        let token = token.trim_matches(['{', '}']);

        // Square brackets → memory address operand with base register
        if token.starts_with('[') {
            let inner = token
                .trim_start_matches('[')
                .trim_end_matches(']')
                .trim_end_matches('!');
            for part in inner.split(',') {
                let part = part.trim();
                if let Some(reg) = try_parse_reg_operand(part) {
                    if out.base_reg.is_none() {
                        out.base_reg = Some(reg);
                    }
                    out.operands.push(Operand::Reg(reg));
                }
            }
            continue;
        }

        // Extract lane index if present (e.g., "v0.s[1]" → "v0.s", Some(1))
        let (token, extracted_lane, extracted_elem_width) = extract_lane_index(token);
        if extracted_lane.is_some() {
            out.lane_index = extracted_lane;
            out.lane_elem_width = extracted_elem_width;
        }

        // Register operand
        if let Some(reg) = try_parse_reg_operand(token) {
            if i == 0 && first_reg_prefix.is_none() {
                first_reg_prefix = token.as_bytes().first().copied();
            }
            out.operands.push(Operand::Reg(reg));
            continue;
        }

        // Immediate (#0x1234, #-5, #123)
        if let Some(val_str) = token.strip_prefix('#') {
            if let Some(val) = parse_imm(val_str) {
                out.operands.push(Operand::Imm(val));
            }
            continue;
        }

        // Address literal (0x... as in branch targets)
        if token.starts_with("0x") || token.starts_with("0X") {
            if let Some(val) = parse_imm(token) {
                out.operands.push(Operand::Imm(val));
            }
            continue;
        }

        // Unrecognized tokens → skip (e.g., shift specifiers like "lsl #3")
    }

    first_reg_prefix
}

/// 按顶层逗号分割操作数，不分割方括号内的逗号。
/// 返回切片引用而非 String，零堆分配。
fn split_operands(text: &str) -> SmallVec<[&str; 6]> {
    let mut result = SmallVec::new();
    let bytes = text.as_bytes();
    let mut start = 0;
    let mut bracket_depth: i32 = 0;

    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'[' => bracket_depth += 1,
            b']' => bracket_depth -= 1,
            b',' if bracket_depth == 0 => {
                result.push(&text[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    if start < text.len() {
        result.push(&text[start..]);
    }
    result
}

/// Try parsing a token as a register, stripping arrangement specifiers (e.g., v0.16b → v0).
fn try_parse_reg_operand(token: &str) -> Option<RegId> {
    let clean = token.split('.').next().unwrap_or(token);
    parse_reg(clean)
}

/// Extract lane index and element width from token like "v0.s[1]".
/// Returns (token without lane bracket, optional lane index, optional elem width in bytes).
fn extract_lane_index(token: &str) -> (&str, Option<u8>, Option<u8>) {
    if let Some(dot_pos) = token.find('.') {
        if let Some(bracket_start) = token[dot_pos..].find('[') {
            let abs_bracket = dot_pos + bracket_start;
            if let Some(bracket_end) = token[abs_bracket..].find(']') {
                let idx_str = &token[abs_bracket + 1..abs_bracket + bracket_end];
                if let Ok(idx) = idx_str.parse::<u8>() {
                    // Extract element width from arrangement specifier between '.' and '['
                    let arrangement = &token[dot_pos + 1..abs_bracket];
                    let elem_width = match arrangement.as_bytes().first() {
                        Some(b'b') => Some(1u8),
                        Some(b'h') => Some(2u8),
                        Some(b's') => Some(4u8),
                        Some(b'd') | Some(b'D') => Some(8u8),
                        _ => None,
                    };
                    return (&token[..abs_bracket], Some(idx), elem_width);
                }
            }
        }
    }
    (token, None, None)
}

/// Parse an immediate value from a string.
/// Handles hex (0x...), negative hex (-0x...), and decimal formats.
fn parse_imm(s: &str) -> Option<i64> {
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16).ok().map(|v| v as i64)
    } else if s.starts_with("-0x") || s.starts_with("-0X") {
        i64::from_str_radix(&s[3..], 16).ok().map(|v| -v)
    } else {
        s.parse::<i64>().ok()
    }
}

/// Extract the first data register's raw name from operand text (e.g., "w8" from "w8, [sp, #0x10]").
///
/// Used for value extraction: we need the original (pre-normalization) register name
/// to search for `regname=0xHEX` patterns in the trace line text.
pub(crate) fn first_data_reg_name(operand_text: &str) -> Option<&str> {
    let first_tok = operand_text.split(',').next()?.trim();
    let first_tok = first_tok
        .trim_start_matches('{')
        .trim_end_matches('}')
        .trim();
    let first_tok = first_tok.split('.').next()?; // strip arrangement specifier
    let b = first_tok.as_bytes();
    if b.len() >= 2
        && matches!(
            b[0],
            b'w' | b'x' | b'q' | b'd' | b's' | b'b' | b'h' | b'v'
        )
        && b[1..].iter().all(|c| c.is_ascii_digit())
    {
        Some(first_tok)
    } else {
        None
    }
}

/// 提取操作数中第二个数据寄存器名（用于 pair 指令如 ldp/stp）。
pub(crate) fn second_data_reg_name(operand_text: &str) -> Option<&str> {
    let mut iter = operand_text.split(',');
    iter.next()?; // 跳过第一个
    let second_tok = iter.next()?.trim();
    let second_tok = second_tok.trim_start_matches('{').trim_end_matches('}').trim();
    let second_tok = second_tok.split('.').next()?;
    let b = second_tok.as_bytes();
    if b.len() >= 2
        && matches!(b[0], b'w' | b'x' | b'q' | b'd' | b's' | b'b' | b'h' | b'v')
        && b[1..].iter().all(|c| c.is_ascii_digit())
    {
        Some(second_tok)
    } else {
        None
    }
}

/// 判断助记符是否为 pair 类指令（ldp/stp 及其变体）。
pub(crate) fn is_pair_mnemonic(mn: &str) -> bool {
    mn.starts_with("ldp") || mn.starts_with("stp")
        || mn.starts_with("ldnp") || mn.starts_with("stnp")
        || mn.starts_with("ldxp") || mn.starts_with("ldaxp")
        || mn.starts_with("stxp") || mn.starts_with("stlxp")
}

/// 判断是否为 SIMD 多寄存器指令（ld1-ld4/st1-st4 且操作数中有两个以上数据寄存器）。
pub(crate) fn is_simd_multi_reg(mnemonic: &str, operand_text: &str) -> bool {
    matches!(mnemonic, "ld1" | "ld2" | "ld3" | "ld4" | "st1" | "st2" | "st3" | "st4")
        && second_data_reg_name(operand_text).is_some()
}

/// 从 `bytes[start_pos..]` 中查找 `reg_name=0xHEX` 模式，返回 HEX 部分的原始字节切片。
///
/// 确保寄存器名精确匹配（不会出现 "x1" 匹配到 "x10" 的前缀冲突），
/// 通过检查名字前一个字符不是字母数字、且名字后紧跟 "=0x"。
fn find_reg_hex_bytes<'a>(bytes: &'a [u8], reg_name: &[u8], start_pos: usize) -> Option<&'a [u8]> {
    let search = &bytes[start_pos..];
    let mut pos = 0;
    while pos + reg_name.len() + 3 <= search.len() {
        let found = memmem::find(&search[pos..], reg_name)?;
        let abs = pos + found;
        let eq_pos = abs + reg_name.len();
        // Check "=0x" follows
        if eq_pos + 3 <= search.len()
            && search[eq_pos] == b'='
            && search[eq_pos + 1] == b'0'
            && search[eq_pos + 2] == b'x'
        {
            // Verify the character before reg_name is not alphanumeric
            let char_before = if abs == 0 {
                b' '
            } else {
                search[abs - 1]
            };
            if !char_before.is_ascii_alphanumeric() {
                let val_start = eq_pos + 3;
                let val_end = search[val_start..]
                    .iter()
                    .position(|b| !b.is_ascii_hexdigit())
                    .map(|p| val_start + p)
                    .unwrap_or(search.len());
                return Some(&search[val_start..val_end]);
            }
        }
        pos = abs + 1;
    }
    None
}

/// Find `reg_name=0xHEX` in `bytes[start_pos..]`, return parsed hex value as u64.
///
/// Ensures exact register name match (no prefix collisions like "x1" matching "x10")
/// by checking the character before the name is not alphanumeric and "=0x" follows immediately.
pub(crate) fn find_reg_value(bytes: &[u8], reg_name: &[u8], start_pos: usize) -> Option<u64> {
    parse_hex_u64(find_reg_hex_bytes(bytes, reg_name, start_pos)?)
}

/// Find `reg_name=0xHEX` in `bytes[start_pos..]`, return parsed hex value as u128.
///
/// 用于 128-bit SIMD q 寄存器值的提取。
pub(crate) fn find_reg_value_u128(bytes: &[u8], reg_name: &[u8], start_pos: usize) -> Option<u128> {
    parse_hex_u128(find_reg_hex_bytes(bytes, reg_name, start_pos)?)
}

/// 将 SIMD 寄存器名的 v/d/s/b/h 前缀转换为 q 前缀。
/// unidbg trace 中 SIMD 寄存器值始终以 q 前缀记录（如 q0=0x...），
/// 但指令操作数可能使用其他前缀（如 v0、d0、s0）。
pub(crate) fn simd_reg_to_q_prefix(reg_name: &str) -> Option<String> {
    let first = reg_name.as_bytes().first()?;
    if matches!(first, b'v' | b'd' | b's' | b'b' | b'h') {
        Some(format!("q{}", &reg_name[1..]))
    } else {
        None
    }
}

/// 判断寄存器名是否为 SIMD 寄存器（v/d/s/b/h 前缀）。
pub(crate) fn is_simd_reg_name(name: &str) -> bool {
    matches!(name.as_bytes().first(), Some(b'v' | b'd' | b's' | b'b' | b'h'))
}

/// 查找 SIMD 寄存器的 u128 值，先尝试 q 前缀（unidbg 格式），
/// 再回退原始寄存器名（某些 trace 直接用 v0=0x... 记录）。
pub(crate) fn find_simd_reg_u128(bytes: &[u8], reg_name: &str, start_pos: usize) -> Option<u128> {
    let q_name = simd_reg_to_q_prefix(reg_name);
    q_name
        .as_deref()
        .and_then(|qn| find_reg_value_u128(bytes, qn.as_bytes(), start_pos))
        .or_else(|| find_reg_value_u128(bytes, reg_name.as_bytes(), start_pos))
}

/// 从 128-bit SIMD 寄存器值中提取标量值。
/// lane load 时提取指定 lane 的元素，64-bit 排列时返回低 64 位。
pub(crate) fn extract_simd_lane_value(full_u128: u128, elem_width: u8, lane_index: Option<u8>) -> u64 {
    if let Some(lane_idx) = lane_index {
        let shift = lane_idx as u32 * elem_width as u32 * 8;
        let mask = if elem_width >= 8 {
            u64::MAX as u128
        } else {
            (1u128 << (elem_width as u32 * 8)) - 1
        };
        ((full_u128 >> shift) & mask) as u64
    } else {
        full_u128 as u64
    }
}

/// 从 SIMD 向量指令的排列说明符推导每个寄存器的访问宽度。
/// - 128-bit 排列 (16b/8h/4s/2d) → 16
/// - 64-bit 排列 (8b/4h/2s/1d) → 8
/// - 其他（lane 说明符如 .s、.d 等）→ None
pub(crate) fn simd_arrangement_total_width(operand_text: &str) -> Option<u8> {
    let first_tok = operand_text.split(',').next()?.trim();
    let first_tok = first_tok.trim_start_matches('{').trim_end_matches('}').trim();
    let first_tok = first_tok.split('[').next()?; // strip lane index
    let arrangement = first_tok.split('.').nth(1)?;
    match arrangement {
        "16b" | "8h" | "4s" | "2d" => Some(16),
        "8b" | "4h" | "2s" | "1d" => Some(8),
        _ => None,
    }
}

/// Infer memory access width from mnemonic and the first operand's raw register prefix.
///
/// The prefix must be captured BEFORE register normalization (w→x, d→v, etc.)
/// because it determines the access width:
/// - w → 4 bytes (32-bit)
/// - x → 8 bytes (64-bit)
/// - s → 4 bytes (single float)
/// - d → 8 bytes (double float)
/// - q → 16 bytes (128-bit vector)
/// - v → 16 bytes (full vector, default)
pub(crate) fn determine_elem_width(mnemonic: &str, first_reg_prefix: Option<u8>) -> u8 {
    match mnemonic {
        "ldrb" | "strb" | "ldrsb" | "ldarb" | "stlrb" | "ldurb" | "sturb" | "ldtrb" | "sttrb"
        | "ldaprb" => 1,
        "ldrh" | "strh" | "ldrsh" | "ldarh" | "stlrh" | "ldurh" | "sturh" | "ldtrh" | "sttrh"
        | "ldaprh" => 2,
        "ldrsw" | "ldursw" | "ldtrsw" | "ldpsw" => 4,
        _ => match first_reg_prefix {
            Some(b'w') => 4,
            Some(b'x') => 8,
            Some(b's') => 4,
            Some(b'd') => 8,
            Some(b'q') => 16,
            Some(b'v') => 16, // default full vector
            _ => 8,           // conservative default
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_standard_computation() {
        let raw = r#"[22:39:18 210][lib.so 0x100] [8b090108] 0x40000108: "add x8, x8, x9" x8=0x5 x9=0xa => x8=0xf"#;
        let line = parse_line(raw).expect("should parse");
        assert_eq!(line.mnemonic.as_str(), "add");
        assert_eq!(line.operands.len(), 3);
        assert_eq!(line.operands[0].as_reg(), Some(RegId::X8));
        assert_eq!(line.operands[1].as_reg(), Some(RegId::X8));
        assert_eq!(line.operands[2].as_reg(), Some(RegId::X9));
        assert!(line.has_arrow);
        assert!(line.mem_op.is_none());
    }

    #[test]
    fn test_parse_memory_write() {
        let raw = r#"[22:39:18 210][lib.so 0x10c] [f9000be8] 0x4000010c: "str x8, [sp, #0x10]" ; mem[WRITE] abs=0xbffff010 x8=0xf sp=0xbffff000 => x8=0xf"#;
        let line = parse_line(raw).expect("should parse");
        assert_eq!(line.mnemonic.as_str(), "str");
        assert_eq!(line.operands.len(), 2); // x8, sp
        assert_eq!(line.operands[0].as_reg(), Some(RegId::X8));
        assert_eq!(line.operands[1].as_reg(), Some(RegId::SP));
        assert_eq!(line.base_reg, Some(RegId::SP));
        let mem = line.mem_op.as_ref().unwrap();
        assert!(mem.is_write);
        assert_eq!(mem.abs, 0xbffff010);
        assert_eq!(mem.elem_width, 8); // x register → 8 bytes
    }

    #[test]
    fn test_parse_memory_read() {
        let raw = r#"[22:39:18 210][lib.so 0x110] [f9400fe0] 0x40000110: "ldr x0, [sp, #0x10]" ; mem[READ] abs=0xbffff010 sp=0xbffff000 => x0=0xf"#;
        let line = parse_line(raw).expect("should parse");
        assert_eq!(line.mnemonic.as_str(), "ldr");
        let mem = line.mem_op.as_ref().unwrap();
        assert!(!mem.is_write);
        assert_eq!(mem.abs, 0xbffff010);
    }

    #[test]
    fn test_parse_mov_pure() {
        let raw = r#"[22:39:18 210][lib.so 0x100] [d2800108] 0x40000100: "mov x8, #5" => x8=0x5"#;
        let line = parse_line(raw).expect("should parse");
        assert_eq!(line.mnemonic.as_str(), "mov");
        assert_eq!(line.operands.len(), 2);
        assert_eq!(line.operands[0].as_reg(), Some(RegId::X8));
        assert!(matches!(line.operands[1], Operand::Imm(5)));
        assert!(line.has_arrow);
    }

    #[test]
    fn test_parse_branch_no_arrow() {
        let raw = r#"[22:39:18 210][lib.so 0x200] [14000010] 0x40000200: "b #0x40000240""#;
        let line = parse_line(raw).expect("should parse");
        assert_eq!(line.mnemonic.as_str(), "b");
        assert!(!line.has_arrow);
    }

    #[test]
    fn test_parse_cmp_nzcv() {
        let raw = r#"[22:39:18 210][lib.so 0x300] [6b09011f] 0x40000300: "cmp x8, x9" x8=0x5 x9=0xa => nzcv=0x80000000"#;
        let line = parse_line(raw).expect("should parse");
        assert_eq!(line.mnemonic.as_str(), "cmp");
        assert_eq!(line.operands[0].as_reg(), Some(RegId::X8));
        assert_eq!(line.operands[1].as_reg(), Some(RegId::X9));
    }

    #[test]
    fn test_parse_cond_branch() {
        let raw = r#"[22:39:18 210][lib.so 0x304] [54000040] 0x40000304: "b.eq #0x4000030c" nzcv=0x40000000"#;
        let line = parse_line(raw).expect("should parse");
        assert_eq!(line.mnemonic.as_str(), "b.eq");
        assert!(!line.has_arrow);
    }

    #[test]
    fn test_parse_invalid_line() {
        assert!(parse_line("").is_none());
        assert!(parse_line("some random log line").is_none());
    }

    #[test]
    fn test_parse_w_register_width() {
        let raw = r#"[22:39:18 210][lib.so 0x10c] [b9001008] 0x4000010c: "str w8, [x0, #0x10]" ; mem[WRITE] abs=0xbffff010 w8=0xf x0=0xbffff000 => w8=0xf"#;
        let line = parse_line(raw).expect("should parse");
        let mem = line.mem_op.as_ref().unwrap();
        assert_eq!(mem.elem_width, 4); // w register → 4 bytes
    }

    // Additional edge-case tests

    #[test]
    fn test_parse_imm_hex() {
        assert_eq!(parse_imm("0x10"), Some(0x10));
        assert_eq!(parse_imm("0xFF"), Some(0xFF));
        assert_eq!(parse_imm("-0x1"), Some(-1));
    }

    #[test]
    fn test_parse_imm_decimal() {
        assert_eq!(parse_imm("5"), Some(5));
        assert_eq!(parse_imm("-3"), Some(-3));
        assert_eq!(parse_imm("0"), Some(0));
    }

    #[test]
    fn test_split_operands_simple() {
        let result = split_operands("x8, x9, x10");
        assert_eq!(result.as_slice(), &["x8", " x9", " x10"]);
    }

    #[test]
    fn test_split_operands_with_brackets() {
        let result = split_operands("[sp, #0x10]");
        assert_eq!(result.as_slice(), &["[sp, #0x10]"]);
    }

    #[test]
    fn test_split_operands_reg_and_bracket() {
        let result = split_operands("x8, [sp, #0x10]");
        assert_eq!(result.as_slice(), &["x8", " [sp, #0x10]"]);
    }

    #[test]
    fn test_determine_elem_width_byte_mnemonics() {
        assert_eq!(determine_elem_width("ldrb", None), 1);
        assert_eq!(determine_elem_width("strb", None), 1);
        assert_eq!(determine_elem_width("ldarb", None), 1);
    }

    #[test]
    fn test_determine_elem_width_half_mnemonics() {
        assert_eq!(determine_elem_width("ldrh", None), 2);
        assert_eq!(determine_elem_width("strh", None), 2);
    }

    #[test]
    fn test_determine_elem_width_by_prefix() {
        assert_eq!(determine_elem_width("ldr", Some(b'w')), 4);
        assert_eq!(determine_elem_width("ldr", Some(b'x')), 8);
        assert_eq!(determine_elem_width("ldr", Some(b's')), 4);
        assert_eq!(determine_elem_width("ldr", Some(b'd')), 8);
        assert_eq!(determine_elem_width("ldr", Some(b'q')), 16);
    }

    #[test]
    fn test_ldpsw_elem_width_is_4() {
        // ldpsw loads 32-bit words (sign-extended to 64-bit x registers)
        // elem_width should be 4, not 8 from the x register prefix
        assert_eq!(determine_elem_width("ldpsw", Some(b'x')), 4);
    }

    #[test]
    fn test_parse_pre_post_arrow_regs() {
        let raw = r#"[22:39:18 210][lib.so 0x100] [8b090108] 0x40000108: "add x8, x8, x9" x8=0x5 x9=0xa => x8=0xf"#;
        let line = parse_line_full(raw).expect("should parse");
        let pre = line.pre_arrow_regs.as_ref().unwrap();
        let post = line.post_arrow_regs.as_ref().unwrap();
        assert!(pre.iter().any(|(r, v)| *r == RegId::X9 && *v == 0xa));
        assert!(pre.iter().any(|(r, v)| *r == RegId::X8 && *v == 0x5));
        assert!(post.iter().any(|(r, v)| *r == RegId::X8 && *v == 0xf));
        assert!(!post.iter().any(|(r, _)| *r == RegId::X9));
    }

    #[test]
    fn test_parse_no_arrow_all_pre() {
        let raw = r#"[22:39:18 210][lib.so 0x200] [14000010] 0x40000200: "b #0x40000240""#;
        let line = parse_line(raw).expect("should parse");
        assert!(!line.has_arrow);
        assert!(line.post_arrow_regs.is_none());
    }

    #[test]
    fn test_parse_cmp_nzcv_arrow_split() {
        let raw = r#"[22:39:18 210][lib.so 0x300] [6b09011f] 0x40000300: "cmp x8, x9" x8=0x5 x9=0xa => nzcv=0x80000000"#;
        let line = parse_line_full(raw).expect("should parse");
        let pre = line.pre_arrow_regs.as_ref().unwrap();
        let post = line.post_arrow_regs.as_ref().unwrap();
        assert_eq!(pre.len(), 2);
        assert_eq!(post.len(), 1);
        assert!(post.iter().any(|(r, _)| *r == RegId::NZCV));
    }

    #[test]
    fn test_parse_mnemonic_only_no_operands() {
        let raw = r#"[22:39:18 210][lib.so 0x100] [d503201f] 0x40000100: "nop""#;
        let line = parse_line(raw).expect("should parse");
        assert_eq!(line.mnemonic.as_str(), "nop");
        assert!(line.operands.is_empty());
        assert!(!line.has_arrow);
    }

    #[test]
    fn test_parse_post_index_writeback() {
        // Post-index form: [sp], #0x10 — no '!' but sp is still modified
        let raw = r#"[00:00:00 001][lib.so 0x100] [a8c17bfd] 0x40000100: "ldp x29, x30, [sp], #0x10" ; mem[READ] abs=0xbffff000 x29=0x0 x30=0x0 sp=0xbffff000 => x29=0x0 x30=0x0 sp=0xbffff010"#;
        let line = parse_line(raw).expect("should parse");
        assert_eq!(line.mnemonic.as_str(), "ldp");
        assert!(
            line.writeback,
            "post-index form should be detected as writeback"
        );
        assert_eq!(line.base_reg, Some(RegId::SP));
    }

    #[test]
    fn test_parse_writeback() {
        let raw = r#"[22:39:18 210][lib.so 0x100] [a9bf7bfd] 0x40000100: "stp x29, x30, [sp, #-0x10]!" ; mem[WRITE] abs=0xbfffeff0 x29=0x0 x30=0x0 sp=0xbffff000 => x29=0x0"#;
        let line = parse_line(raw).expect("should parse");
        assert_eq!(line.mnemonic.as_str(), "stp");
        assert!(line.writeback);
        assert_eq!(line.base_reg, Some(RegId::SP));
    }

    #[test]
    fn test_parse_simd_lane_load() {
        let raw = r#"[00:00:00 001][lib.so 0x100] [0d401de0] 0x40000100: "ld1 {v0.s}[1], [x15]" ; mem[READ] abs=0x40500000 q0=0x0 x15=0x40500000 => q0=0x100"#;
        let line = parse_line(raw).expect("should parse");
        assert_eq!(line.mnemonic.as_str(), "ld1");
        assert_eq!(line.operands.len(), 2);
        assert_eq!(line.operands[0].as_reg(), Some(RegId::V0));
        assert_eq!(line.operands[1].as_reg(), Some(RegId::X15));
        assert_eq!(line.lane_index, Some(1));
    }

    #[test]
    fn test_parse_simd_full_store() {
        let raw = r#"[00:00:00 001][lib.so 0x100] [4c000000] 0x40000100: "st1 {v0.16b}, [x0]" ; mem[WRITE] abs=0x40500000 q0=0xff x0=0x40500000 => q0=0xff"#;
        let line = parse_line(raw).expect("should parse");
        assert_eq!(line.mnemonic.as_str(), "st1");
        assert_eq!(line.operands.len(), 2);
        assert_eq!(line.operands[0].as_reg(), Some(RegId::V0));
        assert_eq!(line.operands[1].as_reg(), Some(RegId::X0));
        assert_eq!(line.lane_index, None);
    }

    #[test]
    fn test_simd_v_prefix_store_value_extraction() {
        // st1 {v0.16b} 的操作数用 v 前缀，但 trace 中值用 q 前缀
        let raw = r#"[00:00:00 001][lib.so 0x100] [4c000000] 0x40000100: "st1 {v0.16b}, [x0]" ; mem[WRITE] abs=0x40500000 q0=0x00000000000000ff00000000000000aa x0=0x40500000"#;
        let line = parse_line(raw).expect("should parse");
        let mem = line.mem_op.as_ref().expect("should have mem op");
        assert_eq!(mem.elem_width, 16);
        assert_eq!(mem.value_lo, Some(0x00000000000000aa));
        assert_eq!(mem.value_hi, Some(0x00000000000000ff));
    }

    #[test]
    fn test_simd_v_prefix_load_value_extraction() {
        // ld1 {v0.16b} LOAD 场景：值在 => 之后
        let raw = r#"[00:00:00 001][lib.so 0x100] [4c400000] 0x40000100: "ld1 {v0.16b}, [x0]" ; mem[READ] abs=0x40500000 q0=0x0 x0=0x40500000 => q0=0x00000000000000020000000000000001"#;
        let line = parse_line(raw).expect("should parse");
        let mem = line.mem_op.as_ref().expect("should have mem op");
        assert_eq!(mem.elem_width, 16);
        assert_eq!(mem.value_lo, Some(0x0000000000000001));
        assert_eq!(mem.value_hi, Some(0x0000000000000002));
    }

    #[test]
    fn test_simd_q_prefix_still_works() {
        // ldr q0 直接用 q 前缀，确保不被破坏
        let raw = r#"[00:00:00 001][lib.so 0x100] [3dc00000] 0x40000100: "ldr q0, [x0]" ; mem[READ] abs=0x40500000 x0=0x40500000 => q0=0x00000000000000030000000000000004"#;
        let line = parse_line(raw).expect("should parse");
        let mem = line.mem_op.as_ref().expect("should have mem op");
        assert_eq!(mem.elem_width, 16);
        assert_eq!(mem.value_lo, Some(0x0000000000000004));
        assert_eq!(mem.value_hi, Some(0x0000000000000003));
    }


    #[test]
    fn test_parse_simd_multi_reg() {
        let raw = r#"[00:00:00 001][lib.so 0x100] [4c402000] 0x40000100: "ld1 {v0.16b, v1.16b}, [x0]" ; mem[READ] abs=0x40500000 q0=0x0 q1=0x0 x0=0x40500000 => q0=0x1 q1=0x2"#;
        let line = parse_line(raw).expect("should parse");
        assert_eq!(line.mnemonic.as_str(), "ld1");
        assert!(line.operands.len() >= 3);
        assert_eq!(line.operands[0].as_reg(), Some(RegId::V0));
        assert_eq!(line.operands[1].as_reg(), Some(RegId::V1));
        assert_eq!(line.operands[2].as_reg(), Some(RegId::X0));
        // 验证第二个寄存器的值被正确提取
        let mem = line.mem_op.as_ref().expect("should have mem_op");
        assert_eq!(mem.elem_width, 16);
        assert_eq!(mem.value_lo, Some(0x1));
        assert_eq!(mem.value_hi, Some(0x0));
        assert_eq!(mem.value2_lo, Some(0x2), "multi-reg ld1 second register value_lo");
        assert_eq!(mem.value2_hi, Some(0x0), "multi-reg ld1 second register value_hi");
    }

    #[test]
    fn test_simd_8b_arrangement_elem_width() {
        // ld1 {v0.8b} 只加载 8 字节，elem_width 应为 8
        let raw = r#"[00:00:00 001][lib.so 0x100] [0c400000] 0x40000100: "ld1 {v0.8b}, [x0]" ; mem[READ] abs=0x40500000 q0=0x0 x0=0x40500000 => q0=0x0807060504030201"#;
        let line = parse_line(raw).expect("should parse");
        let mem = line.mem_op.as_ref().expect("should have mem_op");
        assert_eq!(mem.elem_width, 8, "ld1 {{v0.8b}} should have elem_width=8");
        // 应走 scalar 路径，值为低 64 位
        assert_eq!(mem.value, Some(0x0807060504030201));
        assert!(mem.value_lo.is_none());
        assert!(mem.value_hi.is_none());
    }

    #[test]
    fn test_simd_lane_load_elem_width_and_value() {
        // ld1 {v0.s}[1] 只加载 4 字节到 lane 1，elem_width 应为 4
        // s[1] = bits[63:32]，构造 q0 使 bits[63:32] = 0xaabbccdd
        let raw = r#"[00:00:00 001][lib.so 0x100] [0d401de0] 0x40000100: "ld1 {v0.s}[1], [x15]" ; mem[READ] abs=0x40500000 q0=0x0 x15=0x40500000 => q0=0x0000000000000000aabbccdd00000000"#;
        let line = parse_line(raw).expect("should parse");
        let mem = line.mem_op.as_ref().expect("should have mem_op");
        assert_eq!(mem.elem_width, 4, "lane load should have elem_width=4");
        // lane 1 of .s = bits[63:32] = 0xaabbccdd
        assert_eq!(mem.value, Some(0xaabbccdd), "should extract lane 1 value");
    }

    #[test]
    fn test_simd_multi_reg_8b_arrangement() {
        // ld1 {v0.8b, v1.8b} 加载 16 字节（每个寄存器 8 字节）
        let raw = r#"[00:00:00 001][lib.so 0x100] [0c402000] 0x40000100: "ld1 {v0.8b, v1.8b}, [x0]" ; mem[READ] abs=0x40500000 q0=0x0 q1=0x0 x0=0x40500000 => q0=0x0807060504030201 q1=0x100f0e0d0c0b0a09"#;
        let line = parse_line(raw).expect("should parse");
        let mem = line.mem_op.as_ref().expect("should have mem_op");
        assert_eq!(mem.elem_width, 8);
        assert_eq!(mem.value, Some(0x0807060504030201));
        assert_eq!(mem.value2, Some(0x100f0e0d0c0b0a09), "second reg value for 8b multi-reg");
    }

    #[test]
    fn test_simd_lane_load_v_prefix_trace() {
        // 真实 trace 场景：SIMD 值用 v0=0x... 而非 q0=0x... 记录
        let raw = r#"[07:17:17 416][libtiny.so 0x5335a0] [4091400d] 0x405335a0: "ld1 {v0.s}[1], [x10]" ; mem[READ] abs=0xbfff9288 v0=0x87df82dd x10=0xbfff9288 => v0=0x5b168dc987df82dd"#;
        let line = parse_line(raw).expect("should parse");
        let mem = line.mem_op.as_ref().expect("should have mem_op");
        assert_eq!(mem.elem_width, 4, "lane load elem_width should be 4");
        // s[1] = bits[63:32] of 0x5b168dc987df82dd = 0x5b168dc9
        assert_eq!(mem.value, Some(0x5b168dc9), "should extract lane 1 value from v-prefix trace");
    }

    #[test]
    fn test_extract_lane_index_with_lane() {
        let (rest, lane, elem_width) = extract_lane_index("v0.s[1]");
        assert_eq!(rest, "v0.s");
        assert_eq!(lane, Some(1));
        assert_eq!(elem_width, Some(4));
    }

    #[test]
    fn test_extract_lane_index_without_lane() {
        let (rest, lane, elem_width) = extract_lane_index("v0.16b");
        assert_eq!(rest, "v0.16b");
        assert_eq!(lane, None);
        assert_eq!(elem_width, None);
    }

    #[test]
    fn test_extract_lane_index_no_dot() {
        let (rest, lane, elem_width) = extract_lane_index("x15");
        assert_eq!(rest, "x15");
        assert_eq!(lane, None);
        assert_eq!(elem_width, None);
    }

    #[test]
    fn test_parse_line_empty_string() {
        assert!(parse_line("").is_none());
    }

    #[test]
    fn test_parse_line_no_quotes() {
        let line = r#"[00:00:00 001][lib.so 0x100] [d2800108] 0x40000100: no_quotes_here"#;
        assert!(parse_line(line).is_none());
    }

    #[test]
    fn test_parse_line_single_quote() {
        let line = r#"[00:00:00 001][lib.so 0x100] [d2800108] 0x40000100: "incomplete"#;
        assert!(parse_line(line).is_none());
    }

    #[test]
    fn test_parse_line_empty_mnemonic() {
        let line = r#"[00:00:00 001][lib.so 0x100] [d2800108] 0x40000100: "" => x0=0x0"#;
        assert!(parse_line(line).is_none());
    }

    // =========================================================================
    // Value extraction tests (pass-through pruning)
    // =========================================================================

    #[test]
    fn test_store_value_extraction() {
        let raw = r#"[00:00:00 001][lib.so 0x10c] [f9000000] 0x4000010c: "str x8, [sp, #0x10]" ; mem[WRITE] abs=0xbffff010 x8=0xf sp=0xbffff000 => x8=0xf"#;
        let line = parse_line(raw).expect("should parse");
        let mem = line.mem_op.as_ref().unwrap();
        assert!(mem.is_write);
        assert_eq!(mem.value, Some(0xf));
    }

    #[test]
    fn test_load_value_extraction() {
        let raw = r#"[00:00:00 001][lib.so 0x110] [f9400000] 0x40000110: "ldr x0, [sp, #0x10]" ; mem[READ] abs=0xbffff010 sp=0xbffff000 => x0=0xf"#;
        let line = parse_line(raw).expect("should parse");
        let mem = line.mem_op.as_ref().unwrap();
        assert!(!mem.is_write);
        assert_eq!(mem.value, Some(0xf));
    }

    #[test]
    fn test_strb_value_masking() {
        // strb w8 with full 32-bit value in trace → should mask to 1 byte
        let raw = r#"[00:00:00 001][lib.so 0x10c] [39000108] 0x4000010c: "strb w8, [x0, #0]" ; mem[WRITE] abs=0xbffff010 w8=0x8ecb0cc7 x0=0xbffff010 => w8=0x8ecb0cc7"#;
        let line = parse_line(raw).expect("should parse");
        let mem = line.mem_op.as_ref().unwrap();
        assert_eq!(mem.elem_width, 1);
        assert_eq!(mem.value, Some(0xc7));
    }

    #[test]
    fn test_simd_value_none() {
        // q register (128-bit) → value should be None
        let raw = r#"[00:00:00 001][lib.so 0x100] [3dc00000] 0x40000100: "ldr q0, [x0]" ; mem[READ] abs=0x40500000 x0=0x40500000 => q0=0x12345678"#;
        let line = parse_line(raw).expect("should parse");
        let mem = line.mem_op.as_ref().unwrap();
        assert_eq!(mem.elem_width, 16);
        assert_eq!(mem.value, None);
    }

    #[test]
    fn test_load_value_from_post_arrow_only() {
        // x0 appears before and after arrow with different values
        // LOAD should extract from post-arrow
        let raw = r#"[00:00:00 001][lib.so 0x110] [f9400000] 0x40000110: "ldr x0, [sp, #0x10]" ; mem[READ] abs=0xbffff010 x0=0xdead sp=0xbffff000 => x0=0xbeef"#;
        let line = parse_line(raw).expect("should parse");
        let mem = line.mem_op.as_ref().unwrap();
        assert_eq!(mem.value, Some(0xbeef));
    }

    #[test]
    fn test_first_data_reg_name() {
        assert_eq!(first_data_reg_name("x8, [sp, #0x10]"), Some("x8"));
        assert_eq!(first_data_reg_name("w0, [x1]"), Some("w0"));
        assert_eq!(first_data_reg_name("q0, [x0]"), Some("q0"));
        assert_eq!(first_data_reg_name("{v0.16b}, [x0]"), Some("v0"));
        assert_eq!(first_data_reg_name("[sp, #0x10]"), None);
        assert_eq!(first_data_reg_name(""), None);
    }

    #[test]
    fn test_find_reg_value_basic() {
        let line = b"x8=0xf sp=0xbffff000";
        assert_eq!(find_reg_value(line, b"x8", 0), Some(0xf));
        assert_eq!(find_reg_value(line, b"sp", 0), Some(0xbffff000));
    }

    #[test]
    fn test_find_reg_value_no_prefix_collision() {
        // Searching for "x1" should not match "x10"
        let line = b" x10=0xaaa x1=0xbbb";
        assert_eq!(find_reg_value(line, b"x1", 0), Some(0xbbb));
    }

    #[test]
    fn test_find_reg_value_not_found() {
        let line = b"x8=0xf";
        assert_eq!(find_reg_value(line, b"x9", 0), None);
    }
}
