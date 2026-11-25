"""Expose Wolf Small's FP16 logits as FP32 for Triton's JSON API."""
from pathlib import Path

import onnx
from onnx import TensorProto, helper

root = Path(__file__).resolve().parent
source = root / "source-wolf/model_fp16.onnx"
model = onnx.load(source)
assert [value.name for value in model.graph.input] == ["input_ids", "attention_mask"]
assert len(model.graph.output) == 1
output = model.graph.output[0]
assert output.name == "logits" and output.type.tensor_type.elem_type == TensorProto.FLOAT16
producer = [node for node in model.graph.node if output.name in node.output]
assert len(producer) == 1
node = producer[0]
node.output[list(node.output).index("logits")] = "ark_fp16_logits"
model.graph.node.append(helper.make_node("Cast", ["ark_fp16_logits"], ["logits"], to=TensorProto.FLOAT))
output.type.tensor_type.elem_type = TensorProto.FLOAT
onnx.checker.check_model(model)
onnx.save(model, root / "source-wolf/model_triton.onnx")
