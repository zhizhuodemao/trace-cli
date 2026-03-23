use serde::{Serialize, Deserialize};
use super::types::RegId;

/// 包装 [u64; RegId::COUNT] 以支持 serde（serde 原生不支持长度 > 32 的数组）
#[derive(Clone)]
pub struct RegSnapshot(pub [u64; RegId::COUNT]);

impl Serialize for RegSnapshot {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.as_slice().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RegSnapshot {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let v: Vec<u64> = Vec::deserialize(deserializer)?;
        let arr: [u64; RegId::COUNT] = v.try_into().map_err(|v: Vec<u64>| {
            serde::de::Error::custom(format!("expected {} elements, got {}", RegId::COUNT, v.len()))
        })?;
        Ok(RegSnapshot(arr))
    }
}

#[derive(Serialize, Deserialize)]
pub struct RegCheckpoints {
    pub interval: u32,
    pub snapshots: Vec<RegSnapshot>,
}

impl RegCheckpoints {
    pub fn new(interval: u32) -> Self {
        Self {
            interval,
            snapshots: Vec::new(),
        }
    }

    pub fn save_checkpoint(&mut self, values: &[u64; RegId::COUNT]) {
        self.snapshots.push(RegSnapshot(*values));
    }

    #[allow(dead_code)]
    pub fn get_nearest_before(&self, seq: u32) -> Option<(u32, &[u64; RegId::COUNT])> {
        if self.snapshots.is_empty() {
            return None;
        }
        let idx = (seq / self.interval) as usize;
        let clamped = idx.min(self.snapshots.len() - 1);
        Some((clamped as u32 * self.interval, &self.snapshots[clamped].0))
    }
}
