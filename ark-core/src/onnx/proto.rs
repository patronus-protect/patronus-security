//! Minimal protobuf wire-format reading and writing for ONNX model files.
//!
//! Only what the graph rewrites need: walk the fields of one message, copy encoded fields
//! unchanged and write length-delimited fields. Field numbers follow `onnx.proto3`.

pub(crate) const WIRE_VARINT: u8 = 0;
pub(crate) const WIRE_FIXED64: u8 = 1;
pub(crate) const WIRE_LEN: u8 = 2;
pub(crate) const WIRE_FIXED32: u8 = 5;

pub(crate) const MODEL_GRAPH: u32 = 7;
pub(crate) const GRAPH_INITIALIZER: u32 = 5;
pub(crate) const TENSOR_RAW_DATA: u32 = 9;
pub(crate) const TENSOR_EXTERNAL_DATA: u32 = 13;
pub(crate) const TENSOR_DATA_LOCATION: u32 = 14;
pub(crate) const ENTRY_KEY: u32 = 1;
pub(crate) const ENTRY_VALUE: u32 = 2;
/// `TensorProto.DataLocation.EXTERNAL`.
pub(crate) const LOCATION_EXTERNAL: u64 = 1;

pub(crate) struct Field<'a> {
    pub(crate) number: u32,
    pub(crate) wire: u8,
    /// The varint value, or the length of a length-delimited payload.
    pub(crate) value: u64,
    /// The payload of a length-delimited field.
    pub(crate) payload: &'a [u8],
    /// The whole encoded field, tag included.
    pub(crate) encoded: &'a [u8],
}

pub(crate) fn read_varint(buf: &[u8], pos: &mut usize) -> Result<u64, String> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let byte = *buf.get(*pos).ok_or("truncated varint")?;
        *pos += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err("varint longer than 10 bytes".into())
}

/// Field number and wire type of a field tag.
pub(crate) fn split_tag(tag: u64) -> Result<(u32, u8), String> {
    let number = u32::try_from(tag >> 3).map_err(|_| "field number out of range")?;
    Ok((number, (tag & 7) as u8))
}

pub(crate) fn fields(buf: &[u8]) -> Result<Vec<Field<'_>>, String> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < buf.len() {
        let start = pos;
        let (number, wire) = split_tag(read_varint(buf, &mut pos)?)?;
        let (value, payload) = match wire {
            WIRE_VARINT => (read_varint(buf, &mut pos)?, &buf[0..0]),
            WIRE_LEN => {
                let len = read_varint(buf, &mut pos)?;
                let end = usize::try_from(len)
                    .ok()
                    .and_then(|len| pos.checked_add(len))
                    .filter(|end| *end <= buf.len())
                    .ok_or("length-delimited field overruns its message")?;
                let payload = &buf[pos..end];
                pos = end;
                (len, payload)
            }
            WIRE_FIXED64 | WIRE_FIXED32 => {
                pos += if wire == WIRE_FIXED64 { 8 } else { 4 };
                if pos > buf.len() {
                    return Err("truncated fixed-width field".into());
                }
                (0, &buf[0..0])
            }
            _ => return Err(format!("unsupported wire type {wire}")),
        };
        out.push(Field {
            number,
            wire,
            value,
            payload,
            encoded: &buf[start..pos],
        });
    }
    Ok(out)
}

pub(crate) fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

/// Tag and length of a length-delimited field whose payload follows separately.
pub(crate) fn write_len_header(out: &mut Vec<u8>, number: u32, len: u64) {
    write_varint(out, (u64::from(number) << 3) | u64::from(WIRE_LEN));
    write_varint(out, len);
}

pub(crate) fn write_len_field(out: &mut Vec<u8>, number: u32, payload: &[u8]) {
    write_len_header(out, number, payload.len() as u64);
    out.extend_from_slice(payload);
}

pub(crate) fn write_varint_field(out: &mut Vec<u8>, number: u32, value: u64) {
    write_varint(out, u64::from(number) << 3);
    write_varint(out, value);
}

pub(crate) fn text<'a>(field: &Field<'a>) -> Result<&'a str, String> {
    std::str::from_utf8(field.payload).map_err(|_| "non-UTF-8 name in ONNX graph".into())
}
