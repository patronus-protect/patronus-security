"""Generate a tiny, bounded Loop model for testing actual ORT run termination.

No learned weights or classifier-quality claim. Empty BOS/EOS input runs zero
iterations; content runs 500,000 cheap scalar iterations, allowing cancellation.
"""
from pathlib import Path
import onnx
from onnx import TensorProto, helper

scalar = lambda name, dtype: helper.make_tensor_value_info(name, dtype, [])
body = helper.make_graph(
    [helper.make_node("Identity", ["condition_in"], ["condition_out"]),
     helper.make_node("Add", ["value_in", "one"], ["value_out"])],
    "cancellable_loop_body",
    [scalar("iteration", TensorProto.INT64), scalar("condition_in", TensorProto.BOOL),
     scalar("value_in", TensorProto.FLOAT)],
    [scalar("condition_out", TensorProto.BOOL), scalar("value_out", TensorProto.FLOAT)],
    [helper.make_tensor("one", TensorProto.FLOAT, [], [1.0])],
)
graph = helper.make_graph(
    [helper.make_node("ReduceSum", ["input_ids"], ["sum_ids"], keepdims=0),
     helper.make_node("Greater", ["sum_ids", "special_sum"], ["has_content"]),
     helper.make_node("Cast", ["has_content"], ["content_count"], to=TensorProto.INT64),
     helper.make_node("Mul", ["content_count", "iterations"], ["trip_count"]),
     helper.make_node("Loop", ["trip_count", "condition", "zero"], ["result"], body=body),
     helper.make_node("Cast", ["result"], ["logits"], to=TensorProto.FLOAT16)],
    "wolf_cancellation_test_only",
    [helper.make_tensor_value_info("input_ids", TensorProto.INT64, [1, "sequence"])],
    [scalar("logits", TensorProto.FLOAT16)],
    [helper.make_tensor("special_sum", TensorProto.INT64, [], [3]),
     helper.make_tensor("iterations", TensorProto.INT64, [], [500000]),
     helper.make_tensor("condition", TensorProto.BOOL, [], [True]),
     helper.make_tensor("zero", TensorProto.FLOAT, [], [0.0])],
)
model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 17)], ir_version=8)
onnx.checker.check_model(model)
onnx.save(model, Path(__file__).with_name("wolf_cancellable.onnx"))
