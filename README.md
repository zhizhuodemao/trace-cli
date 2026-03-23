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

## unidbg Setup / unidbg 配置

**⚠️ Required / 必须步骤** — trace-cli requires enhanced unidbg trace output. Standard `traceCode()` output is missing memory addresses, which means `taint`, `memdump`, and `xref` won't work properly.

**⚠️ 必须** — trace-cli 依赖增强版的 unidbg trace 输出。标准 `traceCode()` 缺少内存地址信息，`taint`、`memdump`、`xref` 将无法正常工作。

### Step 1: Replace unidbg files / 替换 unidbg 文件

Copy the two patched files from `unidbg-patch/` to your unidbg source tree:

将 `unidbg-patch/` 下的两个文件复制到你的 unidbg 源码中：

```bash
cp unidbg-patch/AssemblyCodeDumper.java  <your-unidbg>/unidbg-api/src/main/java/com/github/unidbg/AssemblyCodeDumper.java
cp unidbg-patch/RegAccessPrinter.java    <your-unidbg>/unidbg-api/src/main/java/com/github/unidbg/RegAccessPrinter.java
```

Then rebuild unidbg / 然后重新编译 unidbg：

```bash
cd <your-unidbg>
mvn install -DskipTests -Dgpg.skip=true
```

### Step 2: Generate trace / 生成 trace

In your Java test code, use `traceCode()` as usual. The patched files automatically add memory annotations.

在你的 Java 测试代码中，正常使用 `traceCode()`。修改后的文件会自动添加内存注解。

```java
// Enable trace / 开启 trace
TraceHook hook = emulator.traceCode(module.base, module.base + module.size);
hook.setRedirect(new PrintStream(new File("trace.log")));

// Run your target function / 运行目标函数
// ...

// Stop trace / 停止 trace
hook.stopTrace();
```

### What the patch adds / 补丁添加了什么

Standard unidbg output / 标准 unidbg 输出：
```
"ldr x8, [x26, #0x50]" x26=0x123db000 => x8=0x60957206
```

Patched output / 修改后输出：
```
"ldr x8, [x26, #0x50]" ; mem[READ] abs=0x123db050 x26=0x123db000 => x8=0x60957206
"str q0, [x27]" ; mem[WRITE] abs=0x123d6070 q0=0x00...00 x27=0x123d6070 data[0x123d6070]=0x6bc31d303a945570fb1343cbc6dc449f
```

- `; mem[READ/WRITE] abs=0x...` — absolute memory address for every load/store
- `; mem[READ/WRITE] abs=0x...` — 每条 load/store 的内存绝对地址
- `data[0xADDR]=0xHEX` — actual memory content for SIMD stores (delayed read)
- `data[0xADDR]=0xHEX` — SIMD store 的真实内存内容（延迟读取）
- Q/D/S register values in trace output
- Q/D/S SIMD 寄存器值输出

## Install / 安装

### One-liner (recommended) / 一键安装（推荐）

```bash
curl -fsSL https://raw.githubusercontent.com/zhizhuodemao/trace-ui-for-ai/main/install.sh | bash
```

Downloads a pre-built binary + example trace. No Rust needed.

自动下载预编译二进制 + 示例 trace，无需 Rust 环境。

### Try it immediately / 立即体验

```bash
trace-cli example.trace info
trace-cli example.trace search "0x67452301"
trace-cli example.trace taint x0@last --data-only
```

### Build from source / 从源码构建

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
