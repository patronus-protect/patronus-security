"""Expose FP32 logits for Triton's JSON API; keep all model computation FP16."""
from pathlib import Path

import onnx
from onnx import TensorProto, helper

root = Path(__file__).resolve().parent
model = onnx.load(root / "source/model_fp16.onnx")
assert len(model.graph.output) == 7
for output in model.graph.output:
    assert output.type.tensor_type.elem_type in (TensorProto.FLOAT16, TensorProto.FLOAT)
    if output.type.tensor_type.elem_type == TensorProto.FLOAT:
        continue
    name = output.name
    assert all(name not in node.input for node in model.graph.node)
    producers = [node for node in model.graph.node if name in node.output]
    assert len(producers) == 1
    node = producers[0]
    internal = "ark_fp16_" + name
    node.output[list(node.output).index(name)] = internal
    model.graph.node.append(helper.make_node("Cast", [internal], [name], to=TensorProto.FLOAT))
    output.type.tensor_type.elem_type = TensorProto.FLOAT
onnx.checker.check_model(model)
onnx.save(model, root / "source/model_triton.onnx")
