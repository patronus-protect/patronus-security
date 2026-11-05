//! U8S8 → U8U8 rewrite of dynamically quantized ONNX models.
//!
//! Our quantized models multiply `DynamicQuantizeLinear` activations (uint8) with int8 weights
//! in `MatMulInteger` (U8S8). On x86-64 CPUs without VNNI, ONNX Runtime computes U8S8 with
//! `vpmaddubsw`, whose int16 pair sums saturate, so the logits drift far from the arm64 and
//! VNNI results (GLiNER scored "John Smith" 0.002 instead of 0.99 on a Haswell host). Adding
//! 128 to every int8 weight and to its zero point gives the same products as uint8 (U8U8),
//! which ONNX Runtime computes without saturation. The rewrite only touches the protobuf
//! encoding of those initializers; every other byte of the model is copied unchanged.

use std::collections::{HashMap, HashSet};

const WIRE_VARINT: u8 = 0;
const WIRE_FIXED64: u8 = 1;
const WIRE_LEN: u8 = 2;
const WIRE_FIXED32: u8 = 5;

// ONNX protobuf field numbers (onnx.proto3) and tensor element types.
const MODEL_GRAPH: u32 = 7;
const GRAPH_NODE: u32 = 1;
const GRAPH_INITIALIZER: u32 = 5;
const NODE_INPUT: u32 = 1;
const NODE_OUTPUT: u32 = 2;
const NODE_OP_TYPE: u32 = 4;
const TENSOR_DATA_TYPE: u32 = 2;
const TENSOR_INT32_DATA: u32 = 5;
const TENSOR_NAME: u32 = 8;
const TENSOR_RAW_DATA: u32 = 9;
const TENSOR_DATA_LOCATION: u32 = 14;
const UINT8: u64 = 2;
const INT8: u64 = 3;

/// Whether ONNX Runtime's U8S8 integer GEMM saturates on this CPU: x86-64 without VNNI
/// (Intel before Cascade Lake or Alder Lake, AMD before Zen 4).
pub(crate) fn u8s8_saturates() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        !(std::arch::is_x86_feature_detected!("avx512vnni")
            || std::arch::is_x86_feature_detected!("avxvnni"))
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

struct Field<'a> {
    number: u32,
    wire: u8,
    /// The varint value, or the length of a length-delimited payload.
    value: u64,
    /// The payload of a length-delimited field.
    payload: &'a [u8],
    /// The whole encoded field, tag included.
    encoded: &'a [u8],
}

fn read_varint(buf: &[u8], pos: &mut usize) -> Result<u64, String> {
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

fn fields(buf: &[u8]) -> Result<Vec<Field<'_>>, String> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < buf.len() {
        let start = pos;
        let tag = read_varint(buf, &mut pos)?;
        let number = u32::try_from(tag >> 3).map_err(|_| "field number out of range")?;
        let wire = (tag & 7) as u8;
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

fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn write_len_field(out: &mut Vec<u8>, number: u32, payload: &[u8]) {
    write_varint(out, (u64::from(number) << 3) | u64::from(WIRE_LEN));
    write_varint(out, payload.len() as u64);
    out.extend_from_slice(payload);
}

fn text<'a>(field: &Field<'a>) -> Result<&'a str, String> {
    std::str::from_utf8(field.payload).map_err(|_| "non-UTF-8 name in ONNX graph".into())
}

struct Node<'a> {
    op_type: &'a str,
    inputs: Vec<&'a str>,
    outputs: Vec<&'a str>,
}

struct Tensor {
    data_type: u64,
    external: bool,
}

/// The int8 values of an INT8 tensor stored as `raw_data` or `int32_data`.
fn int8_values(tensor: &[Field<'_>]) -> Result<Vec<i8>, String> {
    if let Some(raw) = tensor.iter().find(|field| field.number == TENSOR_RAW_DATA) {
        return Ok(raw.payload.iter().map(|byte| *byte as i8).collect());
    }
    let mut values = Vec::new();
    for field in tensor
        .iter()
        .filter(|field| field.number == TENSOR_INT32_DATA)
    {
        let mut push = |value: u64| -> Result<(), String> {
            let value = value as i64;
            values.push(i8::try_from(value).map_err(|_| "INT8 value out of range")?);
            Ok(())
        };
        if field.wire == WIRE_LEN {
            let mut pos = 0;
            while pos < field.payload.len() {
                push(read_varint(field.payload, &mut pos)?)?;
            }
        } else {
            push(field.value)?;
        }
    }
    Ok(values)
}

/// Re-encode an INT8 initializer as UINT8 (`value + 128`) in `raw_data`, keeping its other fields.
fn uint8_tensor(tensor: &[u8]) -> Result<Vec<u8>, String> {
    let tensor = fields(tensor)?;
    let raw = int8_values(&tensor)?
        .into_iter()
        .map(|value| (value as u8) ^ 0x80)
        .collect::<Vec<_>>();
    let mut out = Vec::with_capacity(raw.len() + 64);
    for field in &tensor {
        if !matches!(
            field.number,
            TENSOR_DATA_TYPE | TENSOR_INT32_DATA | TENSOR_RAW_DATA
        ) {
            out.extend_from_slice(field.encoded);
        }
    }
    write_varint(&mut out, u64::from(TENSOR_DATA_TYPE) << 3);
    write_varint(&mut out, UINT8);
    write_len_field(&mut out, TENSOR_RAW_DATA, &raw);
    Ok(out)
}

/// Rewrite the U8S8 `MatMulInteger` weights of an ONNX model to U8U8.
///
/// Eligible are `MatMulInteger` nodes whose activation comes from `DynamicQuantizeLinear` and
/// whose weight and weight zero point are INT8 initializers. Returns `None` when the model has
/// no such node, or when a candidate initializer has any other consumer: the rewrite is all or
/// nothing, so a partially rewritten model is never produced.
pub(crate) fn rewrite_u8s8_weights<'a>(model: &'a [u8]) -> Result<Option<Vec<u8>>, String> {
    let model_fields = fields(model)?;
    let mut graphs = model_fields
        .iter()
        .filter(|field| field.number == MODEL_GRAPH && field.wire == WIRE_LEN);
    let (Some(graph), None) = (graphs.next(), graphs.next()) else {
        return Err("ONNX model must hold exactly one graph".into());
    };
    let graph_fields = fields(graph.payload)?;

    let mut nodes = Vec::new();
    let mut tensors = HashMap::new();
    for field in &graph_fields {
        match (field.number, field.wire) {
            (GRAPH_NODE, WIRE_LEN) => {
                let mut node = Node {
                    op_type: "",
                    inputs: Vec::new(),
                    outputs: Vec::new(),
                };
                for node_field in fields(field.payload)? {
                    match node_field.number {
                        NODE_INPUT => node.inputs.push(text(&node_field)?),
                        NODE_OUTPUT => node.outputs.push(text(&node_field)?),
                        NODE_OP_TYPE => node.op_type = text(&node_field)?,
                        _ => {}
                    }
                }
                nodes.push(node);
            }
            (GRAPH_INITIALIZER, WIRE_LEN) => {
                let mut name = "";
                let mut tensor = Tensor {
                    data_type: 0,
                    external: false,
                };
                for tensor_field in fields(field.payload)? {
                    match tensor_field.number {
                        TENSOR_NAME => name = text(&tensor_field)?,
                        TENSOR_DATA_TYPE => tensor.data_type = tensor_field.value,
                        TENSOR_DATA_LOCATION => tensor.external = tensor_field.value == 1,
                        _ => {}
                    }
                }
                tensors.insert(name, tensor);
            }
            _ => {}
        }
    }

    let producers = nodes
        .iter()
        .flat_map(|node| {
            node.outputs
                .iter()
                .map(move |output| (*output, node.op_type))
        })
        .collect::<HashMap<_, _>>();
    let is_int8 = |name: &str| {
        tensors
            .get(name)
            .is_some_and(|tensor| tensor.data_type == INT8 && !tensor.external)
    };
    // Weight and weight zero point of a U8S8 MatMulInteger fed by DynamicQuantizeLinear.
    let u8s8_weights = |node: &Node<'a>| -> Option<(&'a str, &'a str)> {
        let (activation, weight, zero_point) = (
            node.inputs.first()?,
            node.inputs.get(1)?,
            node.inputs.get(3)?,
        );
        (node.op_type == "MatMulInteger"
            && producers.get(activation) == Some(&"DynamicQuantizeLinear")
            && is_int8(weight)
            && is_int8(zero_point))
        .then_some((*weight, *zero_point))
    };
    let rewrite = nodes
        .iter()
        .filter_map(&u8s8_weights)
        .flat_map(|(weight, zero_point)| [weight, zero_point])
        .collect::<HashSet<_>>();
    if rewrite.is_empty() {
        return Ok(None);
    }
    // Every use of a rewritten initializer must be the weight or weight zero point of an
    // eligible MatMulInteger; anything else would read the shifted values as int8.
    for node in &nodes {
        for (index, input) in node.inputs.iter().enumerate() {
            if rewrite.contains(input) && !(matches!(index, 1 | 3) && u8s8_weights(node).is_some())
            {
                return Ok(None);
            }
        }
    }

    let mut graph_out = Vec::with_capacity(graph.payload.len() + 1024);
    for field in &graph_fields {
        if field.number == GRAPH_INITIALIZER && field.wire == WIRE_LEN {
            let name = fields(field.payload)?
                .iter()
                .find(|tensor_field| tensor_field.number == TENSOR_NAME)
                .map(text)
                .transpose()?
                .unwrap_or_default();
            if rewrite.contains(name) {
                write_len_field(
                    &mut graph_out,
                    GRAPH_INITIALIZER,
                    &uint8_tensor(field.payload)?,
                );
                continue;
            }
        }
        graph_out.extend_from_slice(field.encoded);
    }
    let mut out = Vec::with_capacity(model.len() + 1024);
    for field in &model_fields {
        if std::ptr::eq(field, graph) {
            write_len_field(&mut out, MODEL_GRAPH, &graph_out);
        } else {
            out.extend_from_slice(field.encoded);
        }
    }
    Ok(Some(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn string_field(out: &mut Vec<u8>, number: u32, value: &str) {
        write_len_field(out, number, value.as_bytes());
    }

    fn varint_field(out: &mut Vec<u8>, number: u32, value: u64) {
        write_varint(out, u64::from(number) << 3);
        write_varint(out, value);
    }

    fn node(op_type: &str, inputs: &[&str], output: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for input in inputs {
            string_field(&mut out, NODE_INPUT, input);
        }
        string_field(&mut out, NODE_OUTPUT, output);
        string_field(&mut out, NODE_OP_TYPE, op_type);
        out
    }

    fn raw_tensor(name: &str, data_type: u64, raw: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        varint_field(&mut out, 1, raw.len() as u64);
        varint_field(&mut out, TENSOR_DATA_TYPE, data_type);
        string_field(&mut out, TENSOR_NAME, name);
        write_len_field(&mut out, TENSOR_RAW_DATA, raw);
        out
    }

    fn int32_tensor(name: &str, values: &[i64]) -> Vec<u8> {
        let mut packed = Vec::new();
        for value in values {
            write_varint(&mut packed, *value as u64);
        }
        let mut out = Vec::new();
        varint_field(&mut out, TENSOR_DATA_TYPE, INT8);
        write_len_field(&mut out, TENSOR_INT32_DATA, &packed);
        string_field(&mut out, TENSOR_NAME, name);
        out
    }

    /// `x -> DynamicQuantizeLinear -> MatMulInteger(q, w, x_zp, w_zp)` plus `extra` nodes.
    fn model(extra: &[Vec<u8>]) -> Vec<u8> {
        let mut graph = Vec::new();
        write_len_field(
            &mut graph,
            GRAPH_NODE,
            &node("DynamicQuantizeLinear", &["x"], "q"),
        );
        write_len_field(
            &mut graph,
            GRAPH_NODE,
            &node("MatMulInteger", &["q", "w", "q_zp", "w_zp"], "y"),
        );
        for node in extra {
            write_len_field(&mut graph, GRAPH_NODE, node);
        }
        write_len_field(
            &mut graph,
            GRAPH_INITIALIZER,
            &raw_tensor("w", INT8, &[0x80, 0xff, 0x00, 0x7f]),
        );
        write_len_field(
            &mut graph,
            GRAPH_INITIALIZER,
            &int32_tensor("w_zp", &[0, -3]),
        );
        write_len_field(
            &mut graph,
            GRAPH_INITIALIZER,
            &raw_tensor("bias", 1, &[1, 2, 3, 4]),
        );
        let mut model = Vec::new();
        varint_field(&mut model, 1, 8);
        write_len_field(&mut model, MODEL_GRAPH, &graph);
        string_field(&mut model, 2, "producer");
        model
    }

    fn initializer<'a>(model: &'a [u8], name: &str) -> Vec<Field<'a>> {
        let graph = fields(model)
            .unwrap()
            .into_iter()
            .find(|field| field.number == MODEL_GRAPH)
            .unwrap()
            .payload;
        fields(graph)
            .unwrap()
            .into_iter()
            .filter(|field| field.number == GRAPH_INITIALIZER)
            .map(|field| fields(field.payload).unwrap())
            .find(|tensor| {
                tensor
                    .iter()
                    .any(|field| field.number == TENSOR_NAME && field.payload == name.as_bytes())
            })
            .unwrap()
    }

    fn data_type_and_raw<'a>(tensor: &[Field<'a>]) -> (u64, &'a [u8]) {
        let data_type = tensor
            .iter()
            .find(|field| field.number == TENSOR_DATA_TYPE)
            .unwrap()
            .value;
        let raw = tensor
            .iter()
            .find(|field| field.number == TENSOR_RAW_DATA)
            .unwrap()
            .payload;
        (data_type, raw)
    }

    #[test]
    fn int8_weights_and_zero_points_become_uint8_plus_128() {
        let rewritten = rewrite_u8s8_weights(&model(&[])).unwrap().unwrap();
        assert_eq!(
            data_type_and_raw(&initializer(&rewritten, "w")),
            (UINT8, &[0x00, 0x7f, 0x80, 0xff][..])
        );
        let zero_point = initializer(&rewritten, "w_zp");
        assert_eq!(data_type_and_raw(&zero_point), (UINT8, &[128, 125][..]));
        assert!(zero_point
            .iter()
            .all(|field| field.number != TENSOR_INT32_DATA));
        assert_eq!(
            data_type_and_raw(&initializer(&rewritten, "bias")),
            (1, &[1, 2, 3, 4][..])
        );
        // Fields outside the graph are copied unchanged.
        let tail = |model: &[u8]| {
            fields(model)
                .unwrap()
                .iter()
                .filter(|field| field.number != MODEL_GRAPH)
                .flat_map(|field| field.encoded.to_vec())
                .collect::<Vec<_>>()
        };
        assert_eq!(tail(&rewritten), tail(&model(&[])));
    }

    #[test]
    fn a_shared_initializer_with_another_consumer_leaves_the_model_unchanged() {
        let model = model(&[node("Gather", &["w", "idx"], "g")]);
        assert!(rewrite_u8s8_weights(&model).unwrap().is_none());
    }

    #[test]
    fn models_without_u8s8_matmul_integer_are_not_rewritten() {
        let mut graph = Vec::new();
        write_len_field(&mut graph, GRAPH_NODE, &node("MatMul", &["x", "w"], "y"));
        write_len_field(
            &mut graph,
            GRAPH_INITIALIZER,
            &raw_tensor("w", INT8, &[1, 2]),
        );
        let mut model = Vec::new();
        write_len_field(&mut model, MODEL_GRAPH, &graph);
        assert!(rewrite_u8s8_weights(&model).unwrap().is_none());
    }

    #[test]
    fn malformed_models_are_rejected() {
        assert!(rewrite_u8s8_weights(&[0x3a, 0x05, 0x01]).is_err());
        assert!(rewrite_u8s8_weights(&[]).is_err());
    }
}
