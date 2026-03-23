use std::io::{BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use sha2::{Sha256, Digest};
use memmap2::Mmap;

const MAGIC: &[u8; 8] = b"TCACHE03";
const MAGIC_V4: &[u8; 8] = b"TCACHE04";
const HEAD_SIZE: usize = 1024 * 1024; // 1MB
const HEADER_LEN_V4: usize = 64;

static CACHE_DIR_OVERRIDE: RwLock<Option<PathBuf>> = RwLock::new(None);

pub fn set_cache_dir_override(path: Option<PathBuf>) {
    *CACHE_DIR_OVERRIDE.write().unwrap() = path;
}

pub fn cache_dir() -> Option<PathBuf> {
    if let Ok(guard) = CACHE_DIR_OVERRIDE.read() {
        if let Some(ref p) = *guard {
            return Some(p.clone());
        }
    }
    dirs::data_dir().map(|d| d.join("trace-ui").join("cache"))
}

fn cache_path(file_path: &str, suffix: &str) -> Option<PathBuf> {
    let mut hasher = Sha256::new();
    hasher.update(file_path.as_bytes());
    let hash = format!("{:x}", hasher.finalize());
    cache_dir().map(|d| d.join(format!("{}{}.bin", hash, suffix)))
}

/// Cache path with explicit extension (no automatic `.bin` suffix).
fn cache_path_ext(file_path: &str, suffix: &str) -> Option<PathBuf> {
    let mut hasher = Sha256::new();
    hasher.update(file_path.as_bytes());
    let hash = format!("{:x}", hasher.finalize());
    cache_dir().map(|d| d.join(format!("{}{}", hash, suffix)))
}

fn head_hash(data: &[u8]) -> [u8; 32] {
    let end = data.len().min(HEAD_SIZE);
    let mut hasher = Sha256::new();
    hasher.update(&data[..end]);
    hasher.finalize().into()
}

fn validate_header(buf: &[u8], data: &[u8]) -> bool {
    if buf.len() < 48 || &buf[0..8] != MAGIC {
        return false;
    }
    let stored_size = u64::from_le_bytes(buf[8..16].try_into().unwrap_or_default());
    if stored_size != data.len() as u64 {
        return false;
    }
    let cached_hash: [u8; 32] = match buf[16..48].try_into() {
        Ok(h) => h,
        Err(_) => return false,
    };
    cached_hash == head_hash(data)
}

fn validate_header_from_reader(reader: &mut impl Read, data: &[u8]) -> bool {
    let mut header = [0u8; 48];
    if reader.read_exact(&mut header).is_err() {
        return false;
    }
    validate_header(&header, data)
}

fn write_header(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&(data.len() as u64).to_le_bytes());
    buf.extend_from_slice(&head_hash(data));
}

// ── 通用加载/保存 (bincode, legacy) ──

fn load_cached<T: serde::de::DeserializeOwned>(file_path: &str, data: &[u8], suffix: &str) -> Option<T> {
    let path = cache_path(file_path, suffix)?;
    let file = std::fs::File::open(&path).ok()?;
    let mut reader = BufReader::new(file);
    if !validate_header_from_reader(&mut reader, data) { return None; }
    bincode::deserialize_from(reader).ok()
}

fn save_cached<T: serde::Serialize>(file_path: &str, data: &[u8], suffix: &str, value: &T) {
    let Some(path) = cache_path(file_path, suffix) else { return };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let file = match std::fs::File::create(&path) {
        Ok(f) => f,
        Err(_) => return,
    };
    let mut writer = BufWriter::new(file);
    let mut header = Vec::with_capacity(48);
    write_header(&mut header, data);
    if writer.write_all(&header).is_err() { return; }
    if bincode::serialize_into(&mut writer, value).is_err() { return; }
    let _ = writer.flush();
}

/// 将预序列化的 bincode 字节写入缓存文件（TCACHE03 header + raw bytes），不依赖 session。
pub fn save_bincode_raw(file_path: &str, data: &[u8], suffix: &str, payload: &[u8]) {
    let Some(path) = cache_path(file_path, suffix) else { return };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let file = match std::fs::File::create(&path) {
        Ok(f) => f,
        Err(_) => return,
    };
    let mut writer = BufWriter::new(file);
    let mut header = Vec::with_capacity(48);
    write_header(&mut header, data);
    if writer.write_all(&header).is_err() { return; }
    if writer.write_all(payload).is_err() { return; }
    let _ = writer.flush();
}

// ── Section-based cache save/load ──

/// 将预序列化的 section 字节写入缓存文件（header + raw bytes），不依赖 session。
pub fn save_sections_raw(file_path: &str, data: &[u8], suffix: &str, section_bytes: &[u8]) {
    let Some(path) = cache_path_ext(file_path, suffix) else { return };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let file = match std::fs::File::create(&path) {
        Ok(f) => f,
        Err(_) => return,
    };
    let mut writer = BufWriter::new(file);

    // Write 64-byte V4 header
    let mut header = Vec::with_capacity(HEADER_LEN_V4);
    header.extend_from_slice(MAGIC_V4);
    header.extend_from_slice(&(data.len() as u64).to_le_bytes());
    header.extend_from_slice(&head_hash(data));
    header.resize(HEADER_LEN_V4, 0); // pad to 64 bytes

    if writer.write_all(&header).is_err() { return; }
    if writer.write_all(section_bytes).is_err() { return; }
    let _ = writer.flush();
    eprintln!("[cache] saved {} ({} + {} bytes)", suffix, HEADER_LEN_V4, section_bytes.len());
}

fn load_cache_mmap(file_path: &str, data: &[u8], suffix: &str) -> Option<Arc<Mmap>> {
    let path = cache_path_ext(file_path, suffix)?;
    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(_) => {
            eprintln!("[cache] {} not found: {:?}", suffix, path);
            return None;
        }
    };
    let mmap = unsafe { Mmap::map(&file) }.ok()?;

    // Validate V4 header
    if mmap.len() < HEADER_LEN_V4 {
        eprintln!("[cache] {} too small: {} bytes", suffix, mmap.len());
        return None;
    }
    if &mmap[0..8] != MAGIC_V4 {
        eprintln!("[cache] {} magic mismatch: {:?}", suffix, &mmap[0..8]);
        return None;
    }
    let stored_size = u64::from_le_bytes(mmap[8..16].try_into().ok()?);
    if stored_size != data.len() as u64 {
        eprintln!("[cache] {} size mismatch: stored={} actual={}", suffix, stored_size, data.len());
        return None;
    }
    let cached_hash: [u8; 32] = mmap[16..48].try_into().ok()?;
    if cached_hash != head_hash(data) {
        eprintln!("[cache] {} hash mismatch", suffix);
        return None;
    }

    eprintln!("[cache] {} loaded: {} bytes", suffix, mmap.len());
    Some(Arc::new(mmap))
}

// ── Section-based cache load ──

pub fn load_phase2_cache(file_path: &str, data: &[u8]) -> Option<Arc<Mmap>> {
    load_cache_mmap(file_path, data, ".p2.cache")
}

pub fn load_scan_cache(file_path: &str, data: &[u8]) -> Option<Arc<Mmap>> {
    load_cache_mmap(file_path, data, ".scan.cache")
}

pub fn load_lidx_cache(file_path: &str, data: &[u8]) -> Option<Arc<Mmap>> {
    load_cache_mmap(file_path, data, ".lidx.cache")
}

/// 删除指定文件的所有缓存
pub fn delete_cache(file_path: &str) {
    // New section-based cache suffixes
    for suffix in [".p2.cache", ".scan.cache", ".lidx.cache", ".strings.bin", ".gum-extra.bin"] {
        if let Some(p) = cache_path_ext(file_path, suffix) {
            let _ = std::fs::remove_file(p);
        }
    }
    // Old rkyv suffixes (cleanup)
    for suffix in [".p2.rkyv", ".scan.rkyv", ".lidx.rkyv"] {
        if let Some(p) = cache_path_ext(file_path, suffix) {
            let _ = std::fs::remove_file(p);
        }
    }
    // Old bincode suffixes (cleanup)
    for suffix in ["", "-scan", "-lidx"] {
        if let Some(p) = cache_path(file_path, suffix) {
            let _ = std::fs::remove_file(p);
        }
    }
}

pub fn get_cache_info() -> (String, u64) {
    let dir = cache_dir().unwrap_or_default();
    let path_str = dir.to_string_lossy().to_string();
    let size = dir_size(&dir);
    (path_str, size)
}

pub fn clear_all_cache() -> (u32, u64) {
    let Some(dir) = cache_dir() else { return (0, 0) };
    let mut count = 0u32;
    let mut total_size = 0u64;
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let ext = path.extension().and_then(|e| e.to_str());
            if ext == Some("bin") || ext == Some("rkyv") || ext == Some("cache") {
                if let Ok(meta) = path.metadata() {
                    total_size += meta.len();
                }
                if std::fs::remove_file(&path).is_ok() {
                    count += 1;
                }
            }
        }
    }
    (count, total_size)
}

fn dir_size(path: &PathBuf) -> u64 {
    let Ok(entries) = std::fs::read_dir(path) else { return 0 };
    entries.flatten()
        .filter_map(|e| e.metadata().ok())
        .map(|m| m.len())
        .sum()
}
