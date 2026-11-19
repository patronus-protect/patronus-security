//! Move inline ONNX weights into an external data file, once, at asset preparation.
//!
//! Published graphs keep their weights inline in the protobuf. ONNX Runtime then reads the
//! whole file into a buffer and builds the initializers from it on the heap. When the weights
//! sit in an external data file next to the graph, ONNX Runtime memory-maps them instead, and
//! clean file-backed pages are not part of the process footprint.
//!
//! [`externalize_weights`] moves every top-level initializer whose `raw_data` holds at least
//! [`MIN_EXTERNAL_BYTES`] into `<graph>.data`, byte for byte. Tensors of 1 MiB or more start at
//! a 64 KiB offset (a multiple of every page size and of the Windows allocation granularity),
//! smaller ones at a 64-byte offset. In the tensor, the `raw_data` field is replaced in place by
//! the `external_data` entries (`location`, `offset`, `length`). An explicit
//! `data_location = DEFAULT` becomes `EXTERNAL` where it stands; without one,
//! `data_location = EXTERNAL` goes right before the entries. Every other byte of the model is
//! kept, so the original file can be rebuilt from the rewrite: the rewrite is committed only when
//! that rebuild hashes (BLAKE3) to the downloaded file, so the initializers are byte-identical
//! and nothing else changed.

use super::proto::{
    fields, split_tag, write_len_field, write_len_header, write_varint_field, Field, ENTRY_KEY,
    ENTRY_VALUE, GRAPH_INITIALIZER, LOCATION_EXTERNAL, MODEL_GRAPH, TENSOR_DATA_LOCATION,
    TENSOR_EXTERNAL_DATA, TENSOR_RAW_DATA, WIRE_FIXED32, WIRE_FIXED64, WIRE_LEN, WIRE_VARINT,
};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

/// Smallest `raw_data` that moves out; the ONNX default size threshold.
const MIN_EXTERNAL_BYTES: u64 = 1024;
const LARGE_TENSOR_BYTES: u64 = 1 << 20;
const LARGE_ALIGNMENT: u64 = 64 * 1024;
const SMALL_ALIGNMENT: u64 = 64;

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// The external data file of an ONNX graph: `model.onnx` → `model.onnx.data`.
pub fn external_data_path(graph: &Path) -> PathBuf {
    let mut name = graph.as_os_str().to_owned();
    name.push(".data");
    PathBuf::from(name)
}

/// Whether the graph at `path` still holds weights inline that [`externalize_weights`] moves.
/// Reads only field headers; weight payloads are skipped.
pub fn has_inline_weights(path: &Path) -> io::Result<bool> {
    Ok(layout(path)?.moves_weights())
}

/// Rewrite the graph at `path` to keep its large initializers in `<path>.data`.
///
/// Idempotent: returns `Ok(false)` without touching anything when no initializer needs to move
/// (already rewritten, or published with external data). Graphs that already reference
/// external data are left as they are. Both files are written next to the graph under
/// temporary names and verified before they replace it: the data file first, the graph last,
/// so a graph on disk always matches its data file.
pub fn externalize_weights(path: &Path) -> io::Result<bool> {
    let layout = layout(path)?;
    if !layout.moves_weights() {
        return Ok(false);
    }
    let data_path = external_data_path(path);
    let location = location(&data_path)?;
    let source_hash = hash_file(path)?;

    let mut source = Source::open(path)?;
    let data_tmp = Temporary::create(&data_path)?;
    let mut data = BufWriter::new(&data_tmp.file);
    let mut offset = 0;
    let mut graph = Vec::new();
    for part in &layout.graph {
        match part {
            Part::Copy(span) => graph.extend(source.read(*span)?),
            Part::Tensor {
                before,
                raw,
                after,
                implicit_location,
            } => {
                let start = aligned(offset, raw.len);
                io::copy(&mut io::repeat(0).take(start - offset), &mut data)?;
                source.copy(*raw, &mut data)?;
                offset = start + raw.len;
                let mut tensor = before.clone();
                if *implicit_location {
                    write_varint_field(&mut tensor, TENSOR_DATA_LOCATION, LOCATION_EXTERNAL);
                }
                external_entries(&mut tensor, &location, start, raw.len);
                tensor.extend_from_slice(after);
                write_len_field(&mut graph, GRAPH_INITIALIZER, &tensor);
            }
        }
    }
    let mut model = Vec::new();
    for field in &layout.model {
        match field {
            Some(span) => model.extend(source.read(*span)?),
            None => write_len_field(&mut model, MODEL_GRAPH, &graph),
        }
    }
    data.flush()?;
    drop(data);
    data_tmp.file.sync_all()?;

    let mut rebuilt = blake3::Hasher::new();
    rebuild(
        &model,
        &mut File::open(&data_tmp.path)?,
        &location,
        &mut rebuilt,
    )?;
    if rebuilt.finalize() != source_hash {
        return Err(invalid(format!(
            "{}: the external-data rewrite does not rebuild the source model",
            path.display()
        )));
    }

    let mut graph_tmp = Temporary::create(path)?;
    graph_tmp.file.write_all(&model)?;
    graph_tmp.file.sync_all()?;
    data_tmp.persist(&data_path)?;
    graph_tmp.persist(path)?;
    Ok(true)
}

/// The model at `path` with its weights inline, as downloaded: rebuilt from the graph and its
/// data file after [`externalize_weights`], the file itself otherwise.
pub(crate) fn inline_model(path: &Path) -> io::Result<Vec<u8>> {
    let model = fs::read(path)?;
    let data_path = external_data_path(path);
    let mut data = match File::open(&data_path) {
        Ok(data) => data,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(model),
        Err(error) => return Err(error),
    };
    let mut out =
        Vec::with_capacity(model.len() + usize::try_from(data.metadata()?.len()).unwrap_or(0));
    rebuild(&model, &mut data, &location(&data_path)?, &mut out)?;
    Ok(out)
}

fn location(data_path: &Path) -> io::Result<String> {
    data_path
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .ok_or_else(|| invalid("ONNX graph file name is not UTF-8"))
}

fn aligned(offset: u64, len: u64) -> u64 {
    let alignment = if len >= LARGE_TENSOR_BYTES {
        LARGE_ALIGNMENT
    } else {
        SMALL_ALIGNMENT
    };
    offset.div_ceil(alignment) * alignment
}

fn external_entries(out: &mut Vec<u8>, location: &str, offset: u64, len: u64) {
    for (key, value) in [
        ("location", location.to_owned()),
        ("offset", offset.to_string()),
        ("length", len.to_string()),
    ] {
        let mut entry = Vec::new();
        write_len_field(&mut entry, ENTRY_KEY, key.as_bytes());
        write_len_field(&mut entry, ENTRY_VALUE, value.as_bytes());
        write_len_field(out, TENSOR_EXTERNAL_DATA, &entry);
    }
}

/// An encoded `data_location` field.
fn data_location(value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    write_varint_field(&mut out, TENSOR_DATA_LOCATION, value);
    out
}

fn hash_file(path: &Path) -> io::Result<blake3::Hash> {
    let mut hasher = blake3::Hasher::new();
    io::copy(&mut File::open(path)?, &mut hasher)?;
    Ok(hasher.finalize())
}

/// A byte range of the source file.
#[derive(Clone, Copy)]
struct Span {
    start: u64,
    len: u64,
}

enum Part {
    /// An encoded graph field copied unchanged.
    Copy(Span),
    /// An initializer whose `raw_data` moves out, with its encoded fields around `raw_data`
    /// (an explicit `data_location` already set to `EXTERNAL`).
    Tensor {
        before: Vec<u8>,
        raw: Span,
        after: Vec<u8>,
        /// The tensor has no `data_location` field of its own.
        implicit_location: bool,
    },
}

struct Layout {
    /// Top-level model fields in file order; `None` is the graph.
    model: Vec<Option<Span>>,
    graph: Vec<Part>,
    /// Whether an initializer already references external data.
    external: bool,
}

impl Layout {
    fn moves_weights(&self) -> bool {
        // A graph that already uses external data keeps its layout.
        !self.external && self.graph.iter().any(|p| matches!(p, Part::Tensor { .. }))
    }
}

struct Header {
    number: u32,
    wire: u8,
    /// Offset of the tag.
    start: u64,
    /// The payload of a length-delimited field; empty otherwise.
    payload: Span,
    /// Offset after the field.
    end: u64,
}

impl Header {
    fn span(&self) -> Span {
        Span {
            start: self.start,
            len: self.end - self.start,
        }
    }
}

/// Sequential reader over the source model that skips payloads by seeking.
struct Source {
    reader: BufReader<File>,
    pos: u64,
    len: u64,
}

impl Source {
    fn open(path: &Path) -> io::Result<Self> {
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        Ok(Self {
            reader: BufReader::with_capacity(64 * 1024, file),
            pos: 0,
            len,
        })
    }

    fn seek(&mut self, to: u64) -> io::Result<()> {
        if to != self.pos {
            let delta = i64::try_from(to).map_err(|_| invalid("offset out of range"))?
                - i64::try_from(self.pos).map_err(|_| invalid("offset out of range"))?;
            self.reader.seek_relative(delta)?;
            self.pos = to;
        }
        Ok(())
    }

    fn varint(&mut self) -> io::Result<u64> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let mut byte = [0u8];
            self.reader.read_exact(&mut byte)?;
            self.pos += 1;
            value |= u64::from(byte[0] & 0x7f) << shift;
            if byte[0] & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(invalid("varint longer than 10 bytes"))
    }

    /// The header of the next field, which must end by `limit`; the reader stays after it.
    fn header(&mut self, limit: u64) -> io::Result<Header> {
        let start = self.pos;
        let (number, wire) = split_tag(self.varint()?).map_err(invalid)?;
        let mut payload = Span {
            start: self.pos,
            len: 0,
        };
        let end = match wire {
            WIRE_VARINT => {
                self.varint()?;
                self.pos
            }
            WIRE_LEN => {
                payload.len = self.varint()?;
                payload.start = self.pos;
                self.pos
                    .checked_add(payload.len)
                    .ok_or_else(|| invalid("field length overflows"))?
            }
            WIRE_FIXED64 => self.pos + 8,
            WIRE_FIXED32 => self.pos + 4,
            _ => return Err(invalid(format!("unsupported wire type {wire}"))),
        };
        if end > limit {
            return Err(invalid("field overruns its message"));
        }
        Ok(Header {
            number,
            wire,
            start,
            payload,
            end,
        })
    }

    fn read(&mut self, span: Span) -> io::Result<Vec<u8>> {
        self.seek(span.start)?;
        let mut out = vec![0; usize::try_from(span.len).map_err(|_| invalid("span too large"))?];
        self.reader.read_exact(&mut out)?;
        self.pos += span.len;
        Ok(out)
    }

    /// Read `span` with the `data_location` field at `location`, if inside, set to `EXTERNAL`.
    fn read_external_location(
        &mut self,
        span: Span,
        location: Option<Span>,
    ) -> io::Result<Vec<u8>> {
        let Some(location) =
            location.filter(|l| l.start >= span.start && l.start < span.start + span.len)
        else {
            return self.read(span);
        };
        let mut out = self.read(Span {
            start: span.start,
            len: location.start - span.start,
        })?;
        out.extend(data_location(LOCATION_EXTERNAL));
        let end = location.start + location.len;
        out.extend(self.read(Span {
            start: end,
            len: span.start + span.len - end,
        })?);
        Ok(out)
    }

    fn copy(&mut self, span: Span, out: &mut impl Write) -> io::Result<()> {
        self.seek(span.start)?;
        let copied = io::copy(&mut (&mut self.reader).take(span.len), out)?;
        self.pos += copied;
        if copied != span.len {
            return Err(invalid("truncated tensor data"));
        }
        Ok(())
    }
}

fn layout(path: &Path) -> io::Result<Layout> {
    let mut source = Source::open(path)?;
    let mut layout = Layout {
        model: Vec::new(),
        graph: Vec::new(),
        external: false,
    };
    let mut graphs = 0;
    while source.pos < source.len {
        let field = source.header(source.len)?;
        if field.number == MODEL_GRAPH && field.wire == WIRE_LEN {
            graphs += 1;
            (layout.graph, layout.external) = graph_parts(&mut source, &field)?;
            layout.model.push(None);
        } else {
            layout.model.push(Some(field.span()));
        }
        source.seek(field.end)?;
    }
    if graphs != 1 {
        return Err(invalid("ONNX model must hold exactly one graph"));
    }
    Ok(layout)
}

/// The graph's parts, and whether an initializer already references external data.
fn graph_parts(source: &mut Source, graph: &Header) -> io::Result<(Vec<Part>, bool)> {
    let mut parts = Vec::new();
    let mut external = false;
    while source.pos < graph.end {
        let field = source.header(graph.end)?;
        let tensor = if field.number == GRAPH_INITIALIZER && field.wire == WIRE_LEN {
            let (tensor, tensor_external) = initializer(source, &field)?;
            external |= tensor_external;
            tensor
        } else {
            None
        };
        parts.push(tensor.unwrap_or(Part::Copy(field.span())));
        source.seek(field.end)?;
    }
    Ok((parts, external))
}

/// The initializer as a [`Part::Tensor`] when its `raw_data` moves out, and whether it
/// already references external data.
fn initializer(source: &mut Source, tensor: &Header) -> io::Result<(Option<Part>, bool)> {
    source.seek(tensor.payload.start)?;
    let mut raw = Vec::new();
    let mut locations = Vec::new();
    let mut external = false;
    while source.pos < tensor.end {
        let field = source.header(tensor.end)?;
        source.seek(field.end)?;
        match field.number {
            TENSOR_RAW_DATA if field.wire == WIRE_LEN => raw.push(field),
            TENSOR_EXTERNAL_DATA => external = true,
            TENSOR_DATA_LOCATION => locations.push(field),
            _ => {}
        }
    }
    let mut location = None;
    for field in &locations {
        source.seek(field.payload.start)?;
        external |= field.wire != WIRE_VARINT || source.varint()? != 0;
        location = Some(field.span());
    }
    // A repeated `raw_data` or `data_location` (last one wins in protobuf) is left inline.
    let ([raw], false, false) = (raw.as_slice(), external, locations.len() > 1) else {
        return Ok((None, external));
    };
    if raw.payload.len < MIN_EXTERNAL_BYTES {
        return Ok((None, false));
    }
    let before = source.read_external_location(
        Span {
            start: tensor.payload.start,
            len: raw.start - tensor.payload.start,
        },
        location,
    )?;
    let after = source.read_external_location(
        Span {
            start: raw.end,
            len: tensor.end - raw.end,
        },
        location,
    )?;
    Ok((
        Some(Part::Tensor {
            before,
            raw: raw.payload,
            after,
            implicit_location: location.is_none(),
        }),
        false,
    ))
}

/// Rebuild the original inline model from a rewritten `model` and its data file into `out`.
fn rebuild(model: &[u8], data: &mut File, location: &str, out: &mut impl Write) -> io::Result<()> {
    let mut pieces = Vec::new();
    for field in fields(model).map_err(invalid)? {
        if field.number == MODEL_GRAPH && field.wire == WIRE_LEN {
            let mut graph = Vec::new();
            for graph_field in fields(field.payload).map_err(invalid)? {
                match (graph_field.number == GRAPH_INITIALIZER && graph_field.wire == WIRE_LEN)
                    .then(|| inline_tensor(graph_field.payload, location))
                    .transpose()?
                    .flatten()
                {
                    Some(tensor) => {
                        graph.push(header(GRAPH_INITIALIZER, &tensor));
                        graph.extend(tensor);
                    }
                    None => graph.push(Piece::Bytes(graph_field.encoded)),
                }
            }
            pieces.push(header(MODEL_GRAPH, &graph));
            pieces.extend(graph);
        } else {
            pieces.push(Piece::Bytes(field.encoded));
        }
    }
    for piece in pieces {
        match piece {
            Piece::Bytes(bytes) => out.write_all(bytes)?,
            Piece::Owned(bytes) => out.write_all(&bytes)?,
            Piece::Data { offset, len } => {
                data.seek(SeekFrom::Start(offset))?;
                if io::copy(&mut (&mut *data).take(len), out)? != len {
                    return Err(invalid("external data file is truncated"));
                }
            }
        }
    }
    Ok(())
}

enum Piece<'a> {
    Bytes(&'a [u8]),
    Owned(Vec<u8>),
    Data { offset: u64, len: u64 },
}

impl Piece<'_> {
    fn len(&self) -> u64 {
        match self {
            Self::Bytes(bytes) => bytes.len() as u64,
            Self::Owned(bytes) => bytes.len() as u64,
            Self::Data { len, .. } => *len,
        }
    }
}

fn header(number: u32, payload: &[Piece<'_>]) -> Piece<'static> {
    let mut out = Vec::new();
    write_len_header(&mut out, number, payload.iter().map(Piece::len).sum());
    Piece::Owned(out)
}

/// The pieces of the inline tensor a rewritten initializer came from; `None` when the tensor
/// keeps its data inline.
fn inline_tensor<'a>(tensor: &'a [u8], location: &str) -> io::Result<Option<Vec<Piece<'a>>>> {
    let tensor_fields = fields(tensor).map_err(invalid)?;
    let entry = |field: &Field<'_>| field.number == TENSOR_EXTERNAL_DATA;
    let Some(first) = tensor_fields.iter().position(entry) else {
        return Ok(None);
    };
    let last = tensor_fields.iter().rposition(entry).unwrap_or(first);
    let (mut file, mut offset, mut len) = (None, None, None);
    for field in &tensor_fields[first..=last] {
        if !entry(field) {
            return Err(invalid("external data entries are not contiguous"));
        }
        let (mut key, mut value) = ("", "");
        for entry in fields(field.payload).map_err(invalid)? {
            let text = std::str::from_utf8(entry.payload)
                .map_err(|_| invalid("non-UTF-8 external data entry"))?;
            match entry.number {
                ENTRY_KEY => key = text,
                ENTRY_VALUE => value = text,
                _ => {}
            }
        }
        let number = || {
            value
                .parse::<u64>()
                .map_err(|_| invalid("bad external entry"))
        };
        match key {
            "location" => file = Some(value),
            "offset" => offset = Some(number()?),
            "length" => len = Some(number()?),
            _ => return Err(invalid("unexpected external data entry")),
        }
    }
    let (Some(file), Some(offset), Some(len)) = (file, offset, len) else {
        return Err(invalid("incomplete external data reference"));
    };
    if file != location {
        return Err(invalid("external data reference to another file"));
    }
    let locations = tensor_fields
        .iter()
        .enumerate()
        .filter(|(_, field)| field.number == TENSOR_DATA_LOCATION)
        .map(|(index, field)| (index, field.value))
        .collect::<Vec<_>>();
    let [(location_index, LOCATION_EXTERNAL)] = locations[..] else {
        return Err(invalid(
            "external tensor needs one data_location = EXTERNAL",
        ));
    };
    // Right before the entries, the rewrite added it; elsewhere it was the tensor's own
    // `data_location = DEFAULT`.
    let added = location_index + 1 == first;
    let mut raw_header = Vec::new();
    write_len_header(&mut raw_header, TENSOR_RAW_DATA, len);
    let mut pieces = Vec::new();
    for (index, field) in tensor_fields.iter().enumerate() {
        if index == first {
            pieces.push(Piece::Owned(std::mem::take(&mut raw_header)));
            pieces.push(Piece::Data { offset, len });
        } else if index == location_index {
            if !added {
                pieces.push(Piece::Owned(data_location(0)));
            }
        } else if !(first..=last).contains(&index) {
            pieces.push(Piece::Bytes(field.encoded));
        }
    }
    Ok(Some(pieces))
}

/// A file created next to its destination that is removed unless persisted.
struct Temporary {
    path: PathBuf,
    file: File,
    persisted: bool,
}

impl Temporary {
    fn create(destination: &Path) -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        loop {
            let mut name = destination.as_os_str().to_owned();
            name.push(format!(
                ".patronus-external-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let path = PathBuf::from(name);
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => {
                    return Ok(Self {
                        path,
                        file,
                        persisted: false,
                    })
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
    }

    fn persist(mut self, destination: &Path) -> io::Result<()> {
        fs::rename(&self.path, destination)?;
        self.persisted = true;
        Ok(())
    }
}

impl Drop for Temporary {
    fn drop(&mut self) {
        if !self.persisted {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Synthetic float models for tests of the rewrite and its callers.
#[cfg(any(test, feature = "test-util"))]
pub mod testing {
    use super::super::proto::{write_len_field, write_varint_field};

    /// One initializer: name, dims, little-endian `raw_data` and an explicit `data_location`
    /// after it. With `EXTERNAL` (1), the tensor points at a published data file instead.
    pub struct Initializer {
        pub name: &'static str,
        pub dims: Vec<u64>,
        pub raw: Vec<u8>,
        pub data_location: Option<u64>,
    }

    fn floats(count: usize, seed: usize) -> Vec<u8> {
        (0..count)
            .flat_map(|i| (((i * 7919 + seed) % 1000) as f32 / 1000.0 - 0.5).to_le_bytes())
            .collect()
    }

    /// `y = (x · w1) · w2 + b` with `x: [1, 512]` and `y: [1, 4]`. `w2` (8 KiB) comes before
    /// `w1` (1 MiB, with an explicit `data_location = DEFAULT` as exporters write it) and `b`
    /// (16 bytes) in the initializer list.
    pub fn model_with_weights() -> Vec<u8> {
        model(&[
            Initializer {
                name: "w2",
                dims: vec![512, 4],
                raw: floats(512 * 4, 1),
                data_location: None,
            },
            Initializer {
                name: "w1",
                dims: vec![512, 512],
                raw: floats(512 * 512, 2),
                data_location: Some(0),
            },
            Initializer {
                name: "b",
                dims: vec![4],
                raw: floats(4, 3),
                data_location: None,
            },
        ])
    }

    /// The graph of [`model_with_weights`] over the given initializers.
    pub fn model(initializers: &[Initializer]) -> Vec<u8> {
        let node = |inputs: &[&str], output: &str, op: &str| {
            let mut node = Vec::new();
            for input in inputs {
                write_len_field(&mut node, 1, input.as_bytes());
            }
            write_len_field(&mut node, 2, output.as_bytes());
            write_len_field(&mut node, 4, op.as_bytes());
            node
        };
        let value_info = |name: &str, dims: &[u64]| {
            let mut shape = Vec::new();
            for dim in dims {
                let mut dimension = Vec::new();
                write_varint_field(&mut dimension, 1, *dim);
                write_len_field(&mut shape, 1, &dimension);
            }
            let mut tensor_type = Vec::new();
            write_varint_field(&mut tensor_type, 1, 1);
            write_len_field(&mut tensor_type, 2, &shape);
            let mut type_proto = Vec::new();
            write_len_field(&mut type_proto, 1, &tensor_type);
            let mut info = Vec::new();
            write_len_field(&mut info, 1, name.as_bytes());
            write_len_field(&mut info, 2, &type_proto);
            info
        };
        let mut graph = Vec::new();
        write_len_field(&mut graph, 1, &node(&["x", "w1"], "h", "MatMul"));
        write_len_field(&mut graph, 1, &node(&["h", "w2"], "z", "MatMul"));
        write_len_field(&mut graph, 1, &node(&["z", "b"], "y", "Add"));
        write_len_field(&mut graph, 2, b"weights");
        for initializer in initializers {
            let mut tensor = Vec::new();
            for dim in &initializer.dims {
                write_varint_field(&mut tensor, 1, *dim);
            }
            write_varint_field(&mut tensor, 2, 1);
            write_len_field(&mut tensor, 8, initializer.name.as_bytes());
            if initializer.data_location == Some(1) {
                let mut entry = Vec::new();
                write_len_field(&mut entry, 1, b"location");
                write_len_field(&mut entry, 2, b"published.bin");
                write_len_field(&mut tensor, 13, &entry);
            } else {
                write_len_field(&mut tensor, 9, &initializer.raw);
            }
            if let Some(location) = initializer.data_location {
                write_varint_field(&mut tensor, 14, location);
            }
            write_len_field(&mut graph, 5, &tensor);
        }
        write_len_field(&mut graph, 11, &value_info("x", &[1, 512]));
        write_len_field(&mut graph, 12, &value_info("y", &[1, 4]));
        let mut opset = Vec::new();
        write_len_field(&mut opset, 1, b"");
        write_varint_field(&mut opset, 2, 13);
        let mut model = Vec::new();
        write_varint_field(&mut model, 1, 8);
        write_len_field(&mut model, 2, b"ark-test");
        write_len_field(&mut model, 7, &graph);
        write_len_field(&mut model, 8, &opset);
        model
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{model, model_with_weights, Initializer};
    use super::*;
    use ort::value::Tensor;

    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "ark-external-data-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let path = self.0.join(name);
            fs::write(&path, bytes).unwrap();
            path
        }
        fn entries(&self) -> usize {
            fs::read_dir(&self.0).unwrap().count()
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// `(name, offset, length)` of every external initializer.
    fn external_tensors(model: &[u8]) -> Vec<(String, u64, u64)> {
        let graph = fields(model)
            .unwrap()
            .into_iter()
            .find(|field| field.number == MODEL_GRAPH)
            .unwrap()
            .payload;
        let mut out = Vec::new();
        for initializer in fields(graph)
            .unwrap()
            .into_iter()
            .filter(|field| field.number == GRAPH_INITIALIZER)
        {
            let tensor = fields(initializer.payload).unwrap();
            let name = tensor.iter().find(|field| field.number == 8).unwrap();
            let mut entries = std::collections::HashMap::new();
            for entry in tensor.iter().filter(|f| f.number == TENSOR_EXTERNAL_DATA) {
                let entry = fields(entry.payload).unwrap();
                entries.insert(entry[0].payload.to_vec(), entry[1].payload.to_vec());
            }
            if entries.is_empty() {
                continue;
            }
            let number = |key: &[u8]| String::from_utf8(entries[key].clone()).unwrap();
            assert_eq!(number(b"location"), "model.onnx.data");
            out.push((
                String::from_utf8(name.payload.to_vec()).unwrap(),
                number(b"offset").parse().unwrap(),
                number(b"length").parse().unwrap(),
            ));
        }
        out
    }

    #[test]
    fn large_initializers_move_out_aligned_and_rebuild_the_source_byte_for_byte() {
        let dir = Directory::new();
        let source = model_with_weights();
        let path = dir.write("model.onnx", &source);
        assert!(has_inline_weights(&path).unwrap());
        assert!(externalize_weights(&path).unwrap());

        let graph = fs::read(&path).unwrap();
        assert!(graph.len() < 1024, "graph keeps {} bytes", graph.len());
        // `w2` (8 KiB) at a 64-byte offset, `w1` (1 MiB) on the next 64 KiB boundary; the
        // 16-byte `b` stays inline.
        assert_eq!(
            external_tensors(&graph),
            [("w2".into(), 0, 8192), ("w1".into(), 65536, 1 << 20)]
        );
        // Both moved tensors read `data_location = EXTERNAL`: `w2` gained the field, `w1` had
        // `DEFAULT` in place.
        assert_eq!(graph.windows(2).filter(|w| *w == [0x70, 0x01]).count(), 2);
        let data = fs::read(external_data_path(&path)).unwrap();
        assert_eq!(data.len(), 65536 + (1 << 20));
        assert!(data[8192..65536].iter().all(|byte| *byte == 0));
        assert_eq!(inline_model(&path).unwrap(), source);
        // Only the graph and its data file remain; no temporaries.
        assert_eq!(dir.entries(), 2);

        // A second preparation finds nothing to move and keeps both files.
        assert!(!has_inline_weights(&path).unwrap());
        assert!(!externalize_weights(&path).unwrap());
        assert_eq!(fs::read(&path).unwrap(), graph);
        assert_eq!(fs::read(external_data_path(&path)).unwrap(), data);
    }

    #[test]
    fn small_weights_and_published_external_data_are_left_alone() {
        let dir = Directory::new();
        let small = dir.write(
            "small.onnx",
            include_bytes!("../../tests/fixtures/wolf_synthetic_fp16.onnx"),
        );
        assert!(!has_inline_weights(&small).unwrap());
        assert!(!externalize_weights(&small).unwrap());

        // One initializer already points at a published data file: the graph keeps its layout
        // even though `w1` is inline.
        let mixed = model(&[
            Initializer {
                name: "w2",
                dims: vec![512, 4],
                raw: Vec::new(),
                data_location: Some(1),
            },
            Initializer {
                name: "w1",
                dims: vec![512, 512],
                raw: vec![0; 1 << 20],
                data_location: None,
            },
        ]);
        let mixed_path = dir.write("mixed.onnx", &mixed);
        assert!(!externalize_weights(&mixed_path).unwrap());
        assert_eq!(fs::read(&mixed_path).unwrap(), mixed);
        assert_eq!(dir.entries(), 2);
    }

    #[test]
    fn malformed_models_are_rejected_without_touching_the_file() {
        let dir = Directory::new();
        let mut truncated = model_with_weights();
        truncated.truncate(truncated.len() / 2);
        for bytes in [&truncated[..], &[0x3a, 0x05, 0x01], &[]] {
            let path = dir.write("model.onnx", bytes);
            assert!(externalize_weights(&path).is_err());
            assert_eq!(fs::read(&path).unwrap(), bytes);
        }
        assert_eq!(dir.entries(), 1);
    }

    #[test]
    fn an_inline_graph_next_to_a_stale_data_file_is_its_own_inline_model() {
        let dir = Directory::new();
        let source = model_with_weights();
        let path = dir.write("model.onnx", &source);
        dir.write("model.onnx.data", b"stale");
        assert_eq!(inline_model(&path).unwrap(), source);
    }

    fn run(path: &Path) -> Vec<f32> {
        let (builder, _) = crate::onnx::configured_session_builder(
            crate::ExecutionBackend::Cpu,
            None,
            crate::OnnxRuntimeOptions::default(),
        )
        .unwrap();
        let mut session = crate::onnx::commit_session(builder, path).unwrap();
        let x = (0..512).map(|i| (i % 17) as f32 / 17.0).collect::<Vec<_>>();
        let outputs = session
            .run(vec![(
                "x",
                Tensor::from_array(([1_usize, 512], x)).unwrap(),
            )])
            .unwrap();
        let (_, y) = outputs
            .get("y")
            .unwrap()
            .try_extract_tensor::<f32>()
            .unwrap();
        y.to_vec()
    }

    #[test]
    fn onnx_runtime_returns_identical_outputs_from_external_weights() {
        let inline = Directory::new();
        let external = Directory::new();
        let source = model_with_weights();
        let inline_path = inline.write("model.onnx", &source);
        let external_path = external.write("model.onnx", &source);
        assert!(externalize_weights(&external_path).unwrap());
        let expected = run(&inline_path);
        assert_eq!(expected.len(), 4);
        assert_eq!(
            run(&external_path)
                .iter()
                .map(|v| v.to_bits())
                .collect::<Vec<_>>(),
            expected.iter().map(|v| v.to_bits()).collect::<Vec<_>>()
        );
    }
}
