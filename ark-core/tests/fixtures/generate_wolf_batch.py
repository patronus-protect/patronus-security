"""Tiny row-sensitive ONNX fixture; no learned weights or model-quality claim.

Logit = sum(masked input IDs) / 10000 + token count / 1000.
Nonzero padding makes incorrect attention masks visible in tests.
Run with the project's venv. Inference tests use Rust and ONNX Runtime.
"""
from pathlib import Path
import onnx
from onnx import TensorProto as T, helper as h

nodes = [
    h.make_node("Cast", ["input_ids"], ["ids"], to=T.FLOAT),
    h.make_node("Cast", ["attention_mask"], ["mask"], to=T.FLOAT),
    h.make_node("Mul", ["ids", "mask"], ["masked"]),
    h.make_node("ReduceSum", ["masked", "axis"], ["total"], keepdims=1),
    h.make_node("ReduceSum", ["mask", "axis"], ["count"], keepdims=1),
    h.make_node("Div", ["total", "scale_ids"], ["id_score"]),
    h.make_node("Div", ["count", "scale_count"], ["count_score"]),
    h.make_node("Add", ["id_score", "count_score"], ["score"]),
]
constants = [h.make_tensor("axis", T.INT64, [1], [1]),
             h.make_tensor("scale_ids", T.FLOAT, [], [10000]),
             h.make_tensor("scale_count", T.FLOAT, [], [1000]),
             h.make_tensor("zero", T.FLOAT, [], [0])]
for binary in [False, True]:
    tail = ([h.make_node("Mul", ["score", "zero"], ["benign"]),
             h.make_node("Concat", ["benign", "score"], ["logits"], axis=1)] if binary else
            [h.make_node("Identity", ["score"], ["logits"])])
    graph = h.make_graph(nodes + tail, "wolf_batch_test_only",
                         [h.make_tensor_value_info(n, T.INT64, ["batch", "sequence"])
                          for n in ["input_ids", "attention_mask"]],
                         [h.make_tensor_value_info("logits", T.FLOAT, ["batch", 2 if binary else 1])],
                         constants)
    model = h.make_model(graph, opset_imports=[h.make_opsetid("", 17)], ir_version=8)
    onnx.checker.check_model(model)
    onnx.save(model, Path(__file__).with_name("wolf_batch_binary.onnx" if binary else "wolf_batch_scalar.onnx"))
