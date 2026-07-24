// SPDX-License-Identifier: GPL-3.0-only
use std::fs;
use std::path::Path;

use std::collections::HashSet;

use redb::{
    Database, MultimapTableDefinition, ReadableDatabase, ReadableMultimapTable, ReadableTable,
    TableDefinition,
};

use super::{
    CacheError, CacheKey, CachedHeadOutput, CachedModelOutput, ExactCacheStore,
    SimilarityStoreRecord,
};

const RECORDS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("exact_model_outputs_v1");
const SIMILARITY_RECORDS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("similarity_records_v1");
const SIMILARITY_BUCKETS: MultimapTableDefinition<&[u8], &[u8]> =
    MultimapTableDefinition::new("similarity_buckets_v1");
const RECORD_MAGIC: &[u8; 8] = b"ARKCACHE";
const SIMILARITY_MAGIC: &[u8; 8] = b"ARKSIM01";
const RECORD_FORMAT_VERSION: u32 = 1;
const MAX_HEADS: usize = 1_024;
const MAX_HEAD_NAME_BYTES: usize = 16 * 1024;
const MAX_LOGITS_PER_HEAD: usize = 1_000_000;

pub(crate) struct RedbCacheStore {
    database: Database,
}

impl RedbCacheStore {
    pub(crate) fn open(path: impl AsRef<Path>) -> Result<Self, CacheError> {
        let path = path.as_ref();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).map_err(storage_error)?;
        }
        prepare_database_file(path)?;
        let database = Database::create(path).map_err(storage_error)?;
        let write = database.begin_write().map_err(storage_error)?;
        write.open_table(RECORDS).map_err(storage_error)?;
        write
            .open_table(SIMILARITY_RECORDS)
            .map_err(storage_error)?;
        write
            .open_multimap_table(SIMILARITY_BUCKETS)
            .map_err(storage_error)?;
        write.commit().map_err(storage_error)?;
        Ok(Self { database })
    }
}

impl ExactCacheStore for RedbCacheStore {
    fn get(
        &self,
        key: &CacheKey,
        now_unix_ms: u64,
    ) -> Result<Option<CachedModelOutput>, CacheError> {
        let key = key.to_bytes();
        let read = self.database.begin_read().map_err(storage_error)?;
        let table = read.open_table(RECORDS).map_err(storage_error)?;
        let Some(value) = table.get(key.as_slice()).map_err(storage_error)? else {
            return Ok(None);
        };
        let output = decode_record(value.value())?;
        if output.is_expired(now_unix_ms) {
            drop(value);
            drop(table);
            drop(read);
            self.remove_key(&key)?;
            return Ok(None);
        }
        Ok(Some(output))
    }

    fn put(&self, key: CacheKey, value: CachedModelOutput) -> Result<(), CacheError> {
        self.put_batch(vec![(key, value)])
    }

    fn put_batch(&self, entries: Vec<(CacheKey, CachedModelOutput)>) -> Result<(), CacheError> {
        let entries = entries
            .into_iter()
            .map(|(key, value)| Ok((key.to_bytes(), encode_record(&value)?)))
            .collect::<Result<Vec<_>, CacheError>>()?;
        let write = self.database.begin_write().map_err(storage_error)?;
        {
            let mut table = write.open_table(RECORDS).map_err(storage_error)?;
            for (key, value) in &entries {
                table
                    .insert(key.as_slice(), value.as_slice())
                    .map_err(storage_error)?;
            }
        }
        write.commit().map_err(storage_error)
    }

    fn remove_expired(&self, now_unix_ms: u64) -> Result<usize, CacheError> {
        let read = self.database.begin_read().map_err(storage_error)?;
        let table = read.open_table(RECORDS).map_err(storage_error)?;
        let mut expired = Vec::new();
        for entry in table.iter().map_err(storage_error)? {
            let (key, value) = entry.map_err(storage_error)?;
            if decode_record(value.value())?.is_expired(now_unix_ms) {
                expired.push(key.value().to_vec());
            }
        }
        drop(table);
        drop(read);

        let similarity_read = self.database.begin_read().map_err(storage_error)?;
        let similarity_table = similarity_read
            .open_table(SIMILARITY_RECORDS)
            .map_err(storage_error)?;
        let mut expired_similarity = Vec::new();
        for entry in similarity_table.iter().map_err(storage_error)? {
            let (id, value) = entry.map_err(storage_error)?;
            let record = decode_similarity_record(id.value(), value.value())?;
            if record.expires_at_unix_ms <= now_unix_ms {
                expired_similarity.push(record);
            }
        }
        drop(similarity_table);
        drop(similarity_read);

        if expired.is_empty() && expired_similarity.is_empty() {
            return Ok(0);
        }
        let write = self.database.begin_write().map_err(storage_error)?;
        {
            let mut table = write.open_table(RECORDS).map_err(storage_error)?;
            for key in &expired {
                table.remove(key.as_slice()).map_err(storage_error)?;
            }
        }
        {
            let mut records = write
                .open_table(SIMILARITY_RECORDS)
                .map_err(storage_error)?;
            let mut buckets = write
                .open_multimap_table(SIMILARITY_BUCKETS)
                .map_err(storage_error)?;
            for record in &expired_similarity {
                records
                    .remove(record.id.as_slice())
                    .map_err(storage_error)?;
                for bucket in &record.bucket_keys {
                    buckets
                        .remove(bucket.as_slice(), record.id.as_slice())
                        .map_err(storage_error)?;
                }
            }
        }
        write.commit().map_err(storage_error)?;
        Ok(expired.len() + expired_similarity.len())
    }

    fn similarity_candidates(
        &self,
        bucket_keys: &[Vec<u8>],
        now_unix_ms: u64,
        limit: usize,
    ) -> Result<Vec<SimilarityStoreRecord>, CacheError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let read = self.database.begin_read().map_err(storage_error)?;
        let buckets = read
            .open_multimap_table(SIMILARITY_BUCKETS)
            .map_err(storage_error)?;
        let records = read.open_table(SIMILARITY_RECORDS).map_err(storage_error)?;
        let mut ids = HashSet::<[u8; 32]>::new();
        'buckets: for bucket in bucket_keys {
            let values = buckets.get(bucket.as_slice()).map_err(storage_error)?;
            for value in values {
                let value = value.map_err(storage_error)?;
                let Ok(id) = <[u8; 32]>::try_from(value.value()) else {
                    continue;
                };
                ids.insert(id);
                if ids.len() >= limit {
                    break 'buckets;
                }
            }
        }
        let mut output = Vec::with_capacity(ids.len());
        for id in ids {
            let Some(value) = records.get(id.as_slice()).map_err(storage_error)? else {
                continue;
            };
            let record = decode_similarity_record(&id, value.value())?;
            if record.expires_at_unix_ms > now_unix_ms {
                output.push(record);
            }
        }
        Ok(output)
    }

    fn put_similarity(&self, record: SimilarityStoreRecord) -> Result<(), CacheError> {
        self.put_similarity_batch(vec![record])
    }

    fn put_similarity_batch(
        &self,
        records_to_write: Vec<SimilarityStoreRecord>,
    ) -> Result<(), CacheError> {
        let encoded = records_to_write
            .into_iter()
            .map(|record| Ok((encode_similarity_record(&record)?, record)))
            .collect::<Result<Vec<_>, CacheError>>()?;
        let write = self.database.begin_write().map_err(storage_error)?;
        {
            let mut records = write
                .open_table(SIMILARITY_RECORDS)
                .map_err(storage_error)?;
            for (bytes, record) in &encoded {
                records
                    .insert(record.id.as_slice(), bytes.as_slice())
                    .map_err(storage_error)?;
            }
        }
        {
            let mut buckets = write
                .open_multimap_table(SIMILARITY_BUCKETS)
                .map_err(storage_error)?;
            for (_, record) in &encoded {
                for bucket in &record.bucket_keys {
                    buckets
                        .insert(bucket.as_slice(), record.id.as_slice())
                        .map_err(storage_error)?;
                }
            }
        }
        write.commit().map_err(storage_error)
    }
}

impl RedbCacheStore {
    fn remove_key(&self, key: &[u8]) -> Result<(), CacheError> {
        let write = self.database.begin_write().map_err(storage_error)?;
        {
            let mut table = write.open_table(RECORDS).map_err(storage_error)?;
            table.remove(key).map_err(storage_error)?;
        }
        write.commit().map_err(storage_error)
    }
}

fn encode_record(output: &CachedModelOutput) -> Result<Vec<u8>, CacheError> {
    if output.heads.len() > MAX_HEADS {
        return Err(CacheError::InvalidRecord(
            "too many model heads".to_string(),
        ));
    }

    let mut bytes = Vec::with_capacity(output.estimated_bytes());
    bytes.extend_from_slice(RECORD_MAGIC);
    push_u32(&mut bytes, RECORD_FORMAT_VERSION);
    push_u32(&mut bytes, output.schema_version);
    push_u64(&mut bytes, output.created_at_unix_ms);
    push_u64(&mut bytes, output.expires_at_unix_ms);
    push_u32(
        &mut bytes,
        u32::try_from(output.heads.len())
            .map_err(|_| CacheError::InvalidRecord("too many model heads".to_string()))?,
    );
    for head in &output.heads {
        if head.head.len() > MAX_HEAD_NAME_BYTES {
            return Err(CacheError::InvalidRecord(
                "model head name is too long".to_string(),
            ));
        }
        if head.logits.len() > MAX_LOGITS_PER_HEAD {
            return Err(CacheError::InvalidRecord(
                "too many logits for model head".to_string(),
            ));
        }
        push_u32(
            &mut bytes,
            u32::try_from(head.head.len()).map_err(|_| {
                CacheError::InvalidRecord("model head name is too long".to_string())
            })?,
        );
        bytes.extend_from_slice(head.head.as_bytes());
        push_u32(
            &mut bytes,
            u32::try_from(head.logits.len()).map_err(|_| {
                CacheError::InvalidRecord("too many logits for model head".to_string())
            })?,
        );
        for logit in &head.logits {
            bytes.extend_from_slice(&logit.to_bits().to_le_bytes());
        }
    }
    Ok(bytes)
}

fn decode_record(bytes: &[u8]) -> Result<CachedModelOutput, CacheError> {
    let mut cursor = Cursor::new(bytes);
    if cursor.take(RECORD_MAGIC.len())? != RECORD_MAGIC {
        return Err(CacheError::InvalidRecord(
            "record magic does not match".to_string(),
        ));
    }
    let format_version = cursor.u32()?;
    if format_version != RECORD_FORMAT_VERSION {
        return Err(CacheError::InvalidRecord(format!(
            "unsupported record format version {format_version}"
        )));
    }
    let schema_version = cursor.u32()?;
    let created_at_unix_ms = cursor.u64()?;
    let expires_at_unix_ms = cursor.u64()?;
    let head_count = cursor.u32()? as usize;
    if head_count > MAX_HEADS {
        return Err(CacheError::InvalidRecord(
            "too many model heads".to_string(),
        ));
    }

    let mut heads = Vec::with_capacity(head_count);
    for _ in 0..head_count {
        let name_len = cursor.u32()? as usize;
        if name_len > MAX_HEAD_NAME_BYTES {
            return Err(CacheError::InvalidRecord(
                "model head name is too long".to_string(),
            ));
        }
        let head = std::str::from_utf8(cursor.take(name_len)?)
            .map_err(|error| CacheError::InvalidRecord(error.to_string()))?
            .to_string();
        let logit_count = cursor.u32()? as usize;
        if logit_count > MAX_LOGITS_PER_HEAD {
            return Err(CacheError::InvalidRecord(
                "too many logits for model head".to_string(),
            ));
        }
        let mut logits = Vec::with_capacity(logit_count);
        for _ in 0..logit_count {
            logits.push(f32::from_bits(cursor.u32()?));
        }
        heads.push(CachedHeadOutput { head, logits });
    }
    if !cursor.is_empty() {
        return Err(CacheError::InvalidRecord(
            "record contains trailing bytes".to_string(),
        ));
    }
    Ok(CachedModelOutput {
        schema_version,
        heads,
        created_at_unix_ms,
        expires_at_unix_ms,
    })
}

fn encode_similarity_record(record: &SimilarityStoreRecord) -> Result<Vec<u8>, CacheError> {
    let mut bytes = Vec::with_capacity(
        record.embedding.len() * 4
            + record
                .heads
                .iter()
                .map(|head| head.logits.len() * 4)
                .sum::<usize>()
            + 256,
    );
    bytes.extend_from_slice(SIMILARITY_MAGIC);
    push_u64(&mut bytes, record.created_at_unix_ms);
    push_u64(&mut bytes, record.expires_at_unix_ms);
    push_bytes(&mut bytes, record.vector_space.as_bytes())?;
    push_bytes(&mut bytes, record.producer_model_sha.as_bytes())?;
    push_u32(
        &mut bytes,
        u32::try_from(record.embedding.len())
            .map_err(|_| CacheError::InvalidRecord("embedding is too large".to_string()))?,
    );
    for value in &record.embedding {
        push_u32(&mut bytes, value.to_bits());
    }
    push_u32(
        &mut bytes,
        u32::try_from(record.heads.len())
            .map_err(|_| CacheError::InvalidRecord("too many model heads".to_string()))?,
    );
    for head in &record.heads {
        push_bytes(&mut bytes, head.head.as_bytes())?;
        push_u32(
            &mut bytes,
            u32::try_from(head.logits.len())
                .map_err(|_| CacheError::InvalidRecord("too many logits".to_string()))?,
        );
        for value in &head.logits {
            push_u32(&mut bytes, value.to_bits());
        }
    }
    push_u32(
        &mut bytes,
        u32::try_from(record.bucket_keys.len())
            .map_err(|_| CacheError::InvalidRecord("too many similarity buckets".to_string()))?,
    );
    for bucket in &record.bucket_keys {
        push_bytes(&mut bytes, bucket)?;
    }
    Ok(bytes)
}

fn decode_similarity_record(id: &[u8], bytes: &[u8]) -> Result<SimilarityStoreRecord, CacheError> {
    let id = <[u8; 32]>::try_from(id)
        .map_err(|_| CacheError::InvalidRecord("invalid similarity record id".to_string()))?;
    let mut cursor = Cursor::new(bytes);
    if cursor.take(SIMILARITY_MAGIC.len())? != SIMILARITY_MAGIC {
        return Err(CacheError::InvalidRecord(
            "similarity record magic does not match".to_string(),
        ));
    }
    let created_at_unix_ms = cursor.u64()?;
    let expires_at_unix_ms = cursor.u64()?;
    let vector_space = cursor.string(MAX_HEAD_NAME_BYTES)?;
    let producer_model_sha = cursor.string(MAX_HEAD_NAME_BYTES)?;
    let embedding_len = cursor.u32()? as usize;
    if embedding_len > MAX_LOGITS_PER_HEAD {
        return Err(CacheError::InvalidRecord(
            "similarity embedding is too large".to_string(),
        ));
    }
    let mut embedding = Vec::with_capacity(embedding_len);
    for _ in 0..embedding_len {
        embedding.push(f32::from_bits(cursor.u32()?));
    }
    let head_count = cursor.u32()? as usize;
    if head_count > MAX_HEADS {
        return Err(CacheError::InvalidRecord(
            "too many similarity heads".to_string(),
        ));
    }
    let mut heads = Vec::with_capacity(head_count);
    for _ in 0..head_count {
        let head = cursor.string(MAX_HEAD_NAME_BYTES)?;
        let logit_count = cursor.u32()? as usize;
        if logit_count > MAX_LOGITS_PER_HEAD {
            return Err(CacheError::InvalidRecord(
                "too many similarity logits".to_string(),
            ));
        }
        let mut logits = Vec::with_capacity(logit_count);
        for _ in 0..logit_count {
            logits.push(f32::from_bits(cursor.u32()?));
        }
        heads.push(CachedHeadOutput { head, logits });
    }
    let bucket_count = cursor.u32()? as usize;
    if bucket_count > 64 {
        return Err(CacheError::InvalidRecord(
            "too many similarity buckets".to_string(),
        ));
    }
    let mut bucket_keys = Vec::with_capacity(bucket_count);
    for _ in 0..bucket_count {
        bucket_keys.push(cursor.bytes(256)?.to_vec());
    }
    if !cursor.is_empty() {
        return Err(CacheError::InvalidRecord(
            "similarity record contains trailing bytes".to_string(),
        ));
    }
    Ok(SimilarityStoreRecord {
        id,
        vector_space,
        producer_model_sha,
        embedding,
        heads,
        bucket_keys,
        created_at_unix_ms,
        expires_at_unix_ms,
    })
}

struct Cursor<'a> {
    remaining: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], CacheError> {
        if self.remaining.len() < len {
            return Err(CacheError::InvalidRecord("record is truncated".to_string()));
        }
        let (value, remaining) = self.remaining.split_at(len);
        self.remaining = remaining;
        Ok(value)
    }

    fn u32(&mut self) -> Result<u32, CacheError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, CacheError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn bytes(&mut self, max_len: usize) -> Result<&'a [u8], CacheError> {
        let len = self.u32()? as usize;
        if len > max_len {
            return Err(CacheError::InvalidRecord(
                "length-prefixed value is too large".to_string(),
            ));
        }
        self.take(len)
    }

    fn string(&mut self, max_len: usize) -> Result<String, CacheError> {
        std::str::from_utf8(self.bytes(max_len)?)
            .map(str::to_string)
            .map_err(|error| CacheError::InvalidRecord(error.to_string()))
    }

    fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_bytes(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), CacheError> {
    push_u32(
        bytes,
        u32::try_from(value.len())
            .map_err(|_| CacheError::InvalidRecord("value is too large".to_string()))?,
    );
    bytes.extend_from_slice(value);
    Ok(())
}

fn storage_error(error: impl std::fmt::Display) -> CacheError {
    CacheError::Storage(error.to_string())
}

#[cfg(unix)]
fn prepare_database_file(path: &Path) -> Result<(), CacheError> {
    use std::fs::OpenOptions;
    use std::io::ErrorKind;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    match OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
    {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            let mut permissions = fs::metadata(path).map_err(storage_error)?.permissions();
            permissions.set_mode(0o600);
            fs::set_permissions(path, permissions).map_err(storage_error)
        }
        Err(error) => Err(storage_error(error)),
    }
}

#[cfg(not(unix))]
fn prepare_database_file(_path: &Path) -> Result<(), CacheError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::cache::CacheNamespace;

    fn temp_path(name: &str) -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("patronus-cache-{name}-{unique}.redb"))
    }

    fn key(value: &str) -> CacheKey {
        CacheKey::for_chunk(
            CacheNamespace::from_components(1, &[b"redb-test"]),
            value.as_bytes(),
        )
    }

    fn output(expires_at_unix_ms: u64) -> CachedModelOutput {
        CachedModelOutput {
            schema_version: 7,
            heads: vec![
                CachedHeadOutput {
                    head: "injection".to_string(),
                    logits: vec![-1.25, 3.5],
                },
                CachedHeadOutput {
                    head: "threat".to_string(),
                    logits: vec![f32::NEG_INFINITY, f32::NAN],
                },
            ],
            created_at_unix_ms: 10,
            expires_at_unix_ms,
        }
    }

    #[test]
    fn binary_record_round_trips_all_float_bits() {
        let expected = output(100);
        let decoded = decode_record(&encode_record(&expected).unwrap()).unwrap();

        assert_eq!(decoded.schema_version, expected.schema_version);
        assert_eq!(decoded.heads[0], expected.heads[0]);
        assert_eq!(
            decoded.heads[1].logits[0].to_bits(),
            expected.heads[1].logits[0].to_bits()
        );
        assert_eq!(
            decoded.heads[1].logits[1].to_bits(),
            expected.heads[1].logits[1].to_bits()
        );
    }

    #[test]
    fn persistent_hit_survives_reopen() {
        let path = temp_path("reopen");
        {
            let store = RedbCacheStore::open(&path).unwrap();
            store.put(key("chunk"), output(100)).unwrap();
        }
        let reopened = RedbCacheStore::open(&path).unwrap();

        let cached = reopened.get(&key("chunk"), 10).unwrap().unwrap();
        assert_eq!(cached.schema_version, 7);
        drop(reopened);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn expired_entries_are_removed_lazily_and_by_cleanup() {
        let path = temp_path("expiry");
        let store = RedbCacheStore::open(&path).unwrap();
        store.put(key("lazy"), output(20)).unwrap();
        store.put(key("sweep"), output(20)).unwrap();
        store.put(key("current"), output(30)).unwrap();

        assert!(store.get(&key("lazy"), 20).unwrap().is_none());
        assert_eq!(store.remove_expired(20).unwrap(), 1);
        assert!(store.get(&key("sweep"), 20).unwrap().is_none());
        assert!(store.get(&key("current"), 20).unwrap().is_some());
        drop(store);
        fs::remove_file(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn database_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let path = temp_path("permissions");
        let store = RedbCacheStore::open(&path).unwrap();

        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(store);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn malformed_records_are_rejected() {
        assert!(decode_record(b"not a cache record").is_err());
        let mut encoded = encode_record(&output(100)).unwrap();
        encoded.push(0);
        assert!(decode_record(&encoded).is_err());
    }
}
