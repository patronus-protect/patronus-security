// SPDX-License-Identifier: GPL-3.0-only
use std::fs;
use std::path::{Path, PathBuf};

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock, RwLock, RwLockReadGuard, Weak};

use redb::{
    Database, DatabaseError, MultimapTableDefinition, ReadableDatabase, ReadableMultimapTable,
    ReadableTable, StorageError, TableDefinition,
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
    path: PathBuf,
    database: RwLock<Database>,
}

impl RedbCacheStore {
    pub(crate) fn open_shared(path: impl AsRef<Path>) -> Result<Arc<Self>, CacheError> {
        static OPEN_STORES: OnceLock<Mutex<HashMap<PathBuf, Weak<RedbCacheStore>>>> =
            OnceLock::new();

        let path = registry_path(path.as_ref())?;
        let mut stores = OPEN_STORES
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .map_err(|_| CacheError::Storage("cache connection registry poisoned".to_string()))?;
        if let Some(store) = stores.get(&path).and_then(Weak::upgrade) {
            return Ok(store);
        }

        let store = Arc::new(Self::open(&path)?);
        stores.insert(path, Arc::downgrade(&store));
        Ok(store)
    }

    pub(crate) fn open(path: impl AsRef<Path>) -> Result<Self, CacheError> {
        let path = path.as_ref().to_path_buf();
        let database = open_database(&path)?;
        Ok(Self {
            path,
            database: RwLock::new(database),
        })
    }

    fn database(&self) -> Result<RwLockReadGuard<'_, Database>, CacheError> {
        if !self.path.exists() {
            let mut database = self
                .database
                .write()
                .map_err(|_| CacheError::Storage("cache database lock poisoned".to_string()))?;
            if !self.path.exists() {
                *database = open_database(&self.path)?;
            }
        }
        self.database
            .read()
            .map_err(|_| CacheError::Storage("cache database lock poisoned".to_string()))
    }
}

impl ExactCacheStore for RedbCacheStore {
    fn get(
        &self,
        key: &CacheKey,
        now_unix_ms: u64,
    ) -> Result<Option<CachedModelOutput>, CacheError> {
        let database = self.database()?;
        let key = key.to_bytes();
        let read = database.begin_read().map_err(storage_error)?;
        let table = read.open_table(RECORDS).map_err(storage_error)?;
        let Some(value) = table.get(key.as_slice()).map_err(storage_error)? else {
            return Ok(None);
        };
        let output = decode_record(value.value())?;
        if output.is_expired(now_unix_ms) {
            drop(value);
            drop(table);
            drop(read);
            remove_key(&database, &key)?;
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
        let database = self.database()?;
        let write = database.begin_write().map_err(storage_error)?;
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
        let database = self.database()?;
        let read = database.begin_read().map_err(storage_error)?;
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

        let similarity_read = database.begin_read().map_err(storage_error)?;
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
        let write = database.begin_write().map_err(storage_error)?;
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

    fn remove_created_before(&self, until_unix_ms: u64) -> Result<usize, CacheError> {
        let database = self.database()?;
        let read = database.begin_read().map_err(storage_error)?;
        let table = read.open_table(RECORDS).map_err(storage_error)?;
        let mut stale = Vec::new();
        for entry in table.iter().map_err(storage_error)? {
            let (key, value) = entry.map_err(storage_error)?;
            if decode_record(value.value())?.created_at_unix_ms < until_unix_ms {
                stale.push(key.value().to_vec());
            }
        }
        drop(table);
        drop(read);

        let similarity_read = database.begin_read().map_err(storage_error)?;
        let similarity_table = similarity_read
            .open_table(SIMILARITY_RECORDS)
            .map_err(storage_error)?;
        let mut stale_similarity = Vec::new();
        for entry in similarity_table.iter().map_err(storage_error)? {
            let (id, value) = entry.map_err(storage_error)?;
            let record = decode_similarity_record(id.value(), value.value())?;
            if record.created_at_unix_ms < until_unix_ms {
                stale_similarity.push(record);
            }
        }
        drop(similarity_table);
        drop(similarity_read);

        if stale.is_empty() && stale_similarity.is_empty() {
            return Ok(0);
        }
        let write = database.begin_write().map_err(storage_error)?;
        {
            let mut table = write.open_table(RECORDS).map_err(storage_error)?;
            for key in &stale {
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
            for record in &stale_similarity {
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
        Ok(stale.len() + stale_similarity.len())
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
        let database = self.database()?;
        let read = database.begin_read().map_err(storage_error)?;
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
        let database = self.database()?;
        let write = database.begin_write().map_err(storage_error)?;
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

fn open_database(path: &Path) -> Result<Database, CacheError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(storage_error)?;
    }
    prepare_database_file(path)?;
    let database = Database::create(path).map_err(database_error)?;
    initialize_tables(&database)?;
    Ok(database)
}

fn registry_path(path: &Path) -> Result<PathBuf, CacheError> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|current_dir| current_dir.join(path))
            .map_err(storage_error)
    }
}

fn initialize_tables(database: &Database) -> Result<(), CacheError> {
    let write = database.begin_write().map_err(storage_error)?;
    write.open_table(RECORDS).map_err(storage_error)?;
    write
        .open_table(SIMILARITY_RECORDS)
        .map_err(storage_error)?;
    write
        .open_multimap_table(SIMILARITY_BUCKETS)
        .map_err(storage_error)?;
    write.commit().map_err(storage_error)
}

fn remove_key(database: &Database, key: &[u8]) -> Result<(), CacheError> {
    let write = database.begin_write().map_err(storage_error)?;
    {
        let mut table = write.open_table(RECORDS).map_err(storage_error)?;
        table.remove(key).map_err(storage_error)?;
    }
    write.commit().map_err(storage_error)
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

fn database_error(error: DatabaseError) -> CacheError {
    match error {
        DatabaseError::DatabaseAlreadyOpen => {
            CacheError::Storage("cache database is already open by another writer".to_string())
        }
        DatabaseError::Storage(StorageError::Corrupted(message)) => {
            CacheError::Storage(format!("cache database is corrupted: {message}"))
        }
        other => storage_error(other),
    }
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
        output_created(10, expires_at_unix_ms)
    }

    fn output_created(created_at_unix_ms: u64, expires_at_unix_ms: u64) -> CachedModelOutput {
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
            created_at_unix_ms,
            expires_at_unix_ms,
        }
    }

    #[test]
    fn open_creates_missing_database_file() {
        let path = temp_path("missing-db");
        assert!(!path.exists());

        let store = RedbCacheStore::open(&path).unwrap();

        assert!(path.exists());
        drop(store);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn open_creates_missing_parent_directory() {
        let path = temp_path("missing-parent")
            .with_extension("")
            .join("nested")
            .join("cache.redb");
        let parent = path.parent().unwrap().to_path_buf();
        assert!(!parent.exists());

        let store = RedbCacheStore::open(&path).unwrap();

        assert!(parent.exists());
        assert!(path.exists());
        drop(store);
        fs::remove_dir_all(parent.parent().unwrap()).unwrap();
    }

    #[test]
    fn deleted_database_file_is_recreated_with_live_handle() {
        let path = temp_path("deleted-live-handle");
        let store = RedbCacheStore::open(&path).unwrap();
        store.put(key("before-delete"), output(100)).unwrap();
        fs::remove_file(&path).unwrap();
        assert!(!path.exists());

        store.put(key("after-delete"), output(100)).unwrap();

        assert!(path.exists());
        assert!(store.get(&key("after-delete"), 10).unwrap().is_some());
        assert!(store.get(&key("before-delete"), 10).unwrap().is_none());
        drop(store);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn deleted_database_file_is_recreated_on_next_open() {
        let path = temp_path("deleted-next-open");
        let store = RedbCacheStore::open(&path).unwrap();
        store.put(key("before-delete"), output(100)).unwrap();
        fs::remove_file(&path).unwrap();
        assert!(!path.exists());

        let reopened = RedbCacheStore::open(&path).unwrap();

        assert!(path.exists());
        assert!(reopened.get(&key("before-delete"), 10).unwrap().is_none());
        reopened.put(key("after-delete"), output(100)).unwrap();
        assert!(reopened.get(&key("after-delete"), 10).unwrap().is_some());
        drop(reopened);
        drop(store);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn corrupt_database_file_remains_an_error() {
        let path = temp_path("corrupt");
        fs::write(&path, b"not a redb database").unwrap();

        let error = match RedbCacheStore::open(&path) {
            Ok(_) => panic!("corrupt database must not be recreated silently"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("corrupt") || error.to_string().contains("invalid"));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn active_second_writer_remains_an_error() {
        let path = temp_path("active-writer");
        let store = RedbCacheStore::open(&path).unwrap();

        let error = match RedbCacheStore::open(&path) {
            Ok(second) => {
                drop(second);
                drop(store);
                fs::remove_file(path).unwrap();
                panic!("active second writer must not be treated as stale cache state");
            }
            Err(error) => error,
        };

        assert!(error.to_string().contains("another writer"));
        drop(store);
        fs::remove_file(path).unwrap();
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

    #[test]
    fn entries_created_before_cutoff_are_removed_by_cleanup() {
        let path = temp_path("created-before");
        let store = RedbCacheStore::open(&path).unwrap();
        store.put(key("old"), output_created(10, 100)).unwrap();
        store.put(key("new"), output_created(20, 100)).unwrap();

        assert_eq!(store.remove_created_before(20).unwrap(), 1);
        assert!(store.get(&key("old"), 20).unwrap().is_none());
        assert!(store.get(&key("new"), 20).unwrap().is_some());
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
