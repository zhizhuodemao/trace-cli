# trace-cli

AI-first ARM64 trace analysis tool. Designed for AI agents (Claude Code) to efficiently analyze unidbg execution traces.

AI 优先的 ARM64 trace 分析工具。专为 AI Agent（Claude Code）设计，高效分析 unidbg 执行轨迹。

> Fork of [trace-ui](https://github.com/imj01y/trace-ui), rebuilt from scratch with an AI-product mindset: the tool hides all complexity (indexing, caching, parsing) and exposes only the capabilities AI needs.
>
> 基于 [trace-ui](https://github.com/anthropics/trace-ui) fork，以 AI 产品思维从零重构：工具隐藏所有复杂度（索引、缓存、解析），只暴露 AI 需要的能力。

## Design Philosophy / 设计理念

- **AI is the explorer, human is the decision-maker** — tool provides capabilities, not interpretations
- **AI 负责探索，人负责决策** — 工具提供能力，不提供解读
- **One bite at a time** — each command returns ≤50 lines, sized for LLM context windows
- **一口一口吃** — 每次调用返回 ≤50 行，适配大模型上下文窗口
- **Zero ceremony** — no sessions, no setup, no index commands. Just query, get results
- **零仪式感** — 无 session、无配置、无索引命令，直接查询直接出结果
- **Auto-everything** — first call auto-indexes (cached for subsequent calls)
- **全自动** — 首次调用自动建索引（后续走缓存）

## Commands / 命令

```bash
# Basic info / 基本信息（3 行：文件、行数、函数数）
trace-cli <file> info

# Read instructions / 查看指令（含寄存器值和内存注解）
trace-cli <file> lines 100-150

# Search for patterns / 搜索模式（取代 grep）
trace-cli <file> search "0x67452301"
trace-cli <file> search "eor " --range 3000-6000

# Backward taint analysis / 反向污点分析（grep 做不到的核心能力）
trace-cli <file> taint x0@last --data-only
trace-cli <file> taint x0@5930 --data-only --range 3000-6000

# Reconstruct memory state / 重构内存状态（提取密钥、常量、查找表）
trace-cli <file> memdump 0x123d6070 64 --at 730000

# Memory cross-references / 内存交叉引用（谁读写了这个地址）
trace-cli <file> xref 0x123df18c
```

## What Each Command Does / 每个命令做什么

| Command | AI's Question / AI 的问题 | What It Returns / 返回什么 |
|---------|--------------------------|---------------------------|
| `info` | "What is this trace?" / "这个 trace 是什么？" | Module name, line count, function count / 模块名、行数、函数数 |
| `lines` | "Show me these instructions" / "给我看这几行指令" | Raw trace lines with registers + memory / 原始 trace 行（含寄存器+内存注解） |
| `search` | "Find this pattern" / "找这个东西" | Matching lines with seq numbers (≤30) / 匹配行+行号（≤30 条） |
| `taint` | "Where does this value come from?" / "这个值从哪来的？" | Backward dependency chain (≤50 lines) / 反向依赖链指令（≤50 行） |
| `memdump` | "What's in memory here?" / "这个地址里存了什么？" | Hexdump from write history / 从写入历史重构的 hexdump |
| `xref` | "Who accesses this address?" / "谁访问了这个地址？" | All reads/writes (≤30) / 所有读写记录（≤30 条） |

## Taint Flags / 污点分析参数

| Flag | Effect / 效果 |
|------|--------------|
| `--data-only` | Cut control flow deps. 26% → 0.14% noise / 切断控制流依赖，噪声从 26% 降到 0.14% |
| `--range START-END` | Only show tainted lines in range / 只显示指定 seq 范围内的污点行 |

## Real-World Validation / 实战验证

Tested on XiaoHongShu's `libxyass.so` shield algorithm (139K lines, heavily obfuscated):

在小红书 `libxyass.so` shield 算法上测试（13.9 万行，重度混淆）：

- `search` located HMAC ipad/opad (`0x36`/`0x5c`), MD5 IV, bswap operations in seconds
- `search` 秒级定位了 HMAC ipad/opad、MD5 IV、bswap 操作
- `taint --data-only` traced HMAC data flow: 36,974 → 199 tainted lines
- `taint --data-only` 追踪 HMAC 数据流：36,974 → 199 行（99.5% 噪声消除）
- `memdump` extracted the full 64-byte HMAC key from AES-CBC decryption output
- `memdump` 从 AES-CBC 解密输出中提取了完整的 64 字节 HMAC key
- Algorithm structure (HMAC-MD5 → RC4 → Base64) identified in ~10 CLI calls
- 约 10 次 CLI 调用即识别出完整算法结构（HMAC-MD5 → RC4 → Base64）

## unidbg Integration / unidbg 集成

This tool requires enhanced trace output from unidbg. The modifications to `AssemblyCodeDumper.java` and `RegAccessPrinter.java` add:

本工具需要增强版的 unidbg trace 输出。对 `AssemblyCodeDumper.java` 和 `RegAccessPrinter.java` 的修改：

- `; mem[READ/WRITE] abs=0x...` — absolute memory addresses for all load/store
- `; mem[READ/WRITE] abs=0x...` — 所有 load/store 指令的内存绝对地址
- `data[0xADDR]=0xHEX` — delayed memory reads for SIMD stores (workaround for `reg_read_vector` bug)
- `data[0xADDR]=0xHEX` — SIMD store 的延迟内存读取（绕过 `reg_read_vector` 在 CodeHook 中返回旧值的 bug）
- Q/D/S SIMD register value output
- Q/D/S SIMD 寄存器值输出

## Build / 构建

```bash
# Requires Rust 1.75+
cargo build --release

# Binary at / 二进制文件位于 target/release/trace-cli
```

## Architecture / 架构

```
trace file (mmap, zero-copy)
    │
    ▼
auto-index on first call (parallel scan, cached to disk)
首次调用自动索引（并行扫描，缓存到磁盘）
    │
    ▼
6 commands → structured text output → AI agent
6 个命令 → 结构化文本输出 → AI Agent
```

Core algorithms carried over from trace-ui / 核心算法继承自 trace-ui：

- ARM64 instruction parser (unidbg format) / ARM64 指令解析器（unidbg 格式）
- DEF-USE data flow analysis / DEF-USE 数据流分析
- Backward taint slicing (BFS on dependency graph) / 反向污点切片（依赖图上的 BFS）
- Call tree builder (BL/BLR/RET matching) / 调用树构建（BL/BLR/RET 配对）
- Memory access index / 内存访问索引
- Register checkpoints (every 1000 lines) / 寄存器快照（每 1000 行）
- Line index (sampled every 256 lines for O(1) access) / 行索引（每 256 行采样，O(1) 随机访问）
- Disk cache with SHA-256 validation / 磁盘缓存 + SHA-256 校验

## License / 许可证

[Personal Use License](LICENSE)
