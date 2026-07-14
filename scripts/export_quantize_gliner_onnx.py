#!/usr/bin/env python3
"""Export classic GLiNER to ONNX with UINT4 embeddings and INT8 MatMuls."""

import argparse
import json
import shutil
from collections import Counter
from pathlib import Path

import onnx
from gliner import GLiNER
from huggingface_hub import hf_hub_download
from onnxruntime.quantization import QuantType, quantize_dynamic
from onnxruntime.quantization.matmul_nbits_quantizer import MatMulNBitsQuantizer


DEFAULT_REPO = "gliner-community/gliner_small-v2.5"
DEFAULT_REVISION = "f227d3cd637bd4e6757ae143935316d062393341"
RUNTIME_ASSETS = (
    "gliner_config.json",
    "special_tokens_map.json",
    "spm.model",
    "tokenizer.json",
    "tokenizer_config.json",
)


def inline_initializer_identities(source: Path, destination: Path) -> int:
    model = onnx.load(source, load_external_data=False)
    initializer_names = {item.name for item in model.graph.initializer}
    graph_outputs = {item.name for item in model.graph.output}
    aliases: dict[str, str] = {}
    retained_nodes = []

    for node in model.graph.node:
        source_name = aliases.get(node.input[0], node.input[0]) if node.input else ""
        if (
            node.op_type == "Identity"
            and len(node.input) == 1
            and len(node.output) == 1
            and source_name in initializer_names
            and node.output[0] not in graph_outputs
        ):
            aliases[node.output[0]] = source_name
        else:
            retained_nodes.append(node)

    for node in retained_nodes:
        for index, name in enumerate(node.input):
            node.input[index] = aliases.get(name, name)

    del model.graph.node[:]
    model.graph.node.extend(retained_nodes)
    onnx.save_model(model, destination)
    return len(aliases)


def word_embedding_gathers(path: Path) -> list[str]:
    model = onnx.load(path, load_external_data=False)
    initializers = {item.name: item for item in model.graph.initializer}
    matches = []
    for node in model.graph.node:
        if node.op_type != "Gather" or not node.input:
            continue
        weight = initializers.get(node.input[0])
        if weight is not None and len(weight.dims) == 2 and weight.dims[0] >= 100_000:
            matches.append(node.name)
    if len(matches) != 1:
        raise RuntimeError(f"expected one word-embedding Gather, found {matches}")
    return matches


def validate_quantized_model(path: Path) -> dict[str, object]:
    model = onnx.load(path, load_external_data=False)
    initializers = {item.name: item for item in model.graph.initializer}
    aliases = {
        node.output[0]: node.input[0]
        for node in model.graph.node
        if node.op_type == "Identity"
        and len(node.input) == 1
        and node.input[0] in initializers
    }
    float_weight_matmuls = []
    for node in model.graph.node:
        if node.op_type != "MatMul" or len(node.input) < 2:
            continue
        weight = initializers.get(aliases.get(node.input[1], node.input[1]))
        if weight is not None and weight.data_type == onnx.TensorProto.FLOAT:
            float_weight_matmuls.append(node.name)

    counts = Counter(node.op_type for node in model.graph.node)
    if float_weight_matmuls:
        raise RuntimeError(
            "FP32 MatMul weights remain after quantization: "
            + ", ".join(float_weight_matmuls)
        )
    if counts["MatMulInteger"] == 0:
        raise RuntimeError("no MatMulInteger nodes found after INT8 quantization")
    if counts["GatherBlockQuantized"] != 1:
        raise RuntimeError(
            "expected one UINT4 GatherBlockQuantized node, "
            f"found {counts['GatherBlockQuantized']}"
        )

    dtype_bytes = Counter()
    for item in model.graph.initializer:
        dtype = onnx.TensorProto.DataType.Name(item.data_type)
        dtype_bytes[dtype] += len(item.raw_data)
    return {
        "matmul_integer_nodes": counts["MatMulInteger"],
        "gather_block_quantized_nodes": counts["GatherBlockQuantized"],
        "initializer_mib": {
            dtype: round(size / 1024 / 1024, 3)
            for dtype, size in sorted(dtype_bytes.items())
        },
    }


def export_and_quantize(args: argparse.Namespace) -> None:
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    fp32 = output / "model_fp32.onnx"
    inlined = output / "model_identity_inlined.onnx"
    int4_embeddings = output / "model_int4_embeddings.onnx"
    quantized = output / "model_int4_embeddings_int8.onnx"

    model = GLiNER.from_pretrained(
        args.repo,
        revision=args.revision,
        cache_dir=args.cache_dir,
        variant="fp16",
        dtype="fp16",
        low_cpu_mem_usage=True,
    )
    tokenizer = model.data_processor.transformer_tokenizer
    runtime_config = {
        "max_len": model.config.max_len,
        "max_width": model.config.max_width,
        "special_tokens": {
            token: tokenizer.convert_tokens_to_ids(token)
            for token in (
                tokenizer.cls_token,
                tokenizer.sep_token,
                model.config.ent_token,
                model.config.sep_token,
            )
        },
        "model_file": quantized.name,
    }
    model.model.float()
    model.export_to_onnx(
        output,
        onnx_filename=fp32.name,
        quantize=False,
        opset=19,
    )
    del model

    for filename in RUNTIME_ASSETS:
        source = hf_hub_download(
            repo_id=args.repo,
            filename=filename,
            revision=args.revision,
            cache_dir=args.cache_dir,
        )
        shutil.copyfile(source, output / filename)
    with (output / "gliner_onnx_config.json").open("w") as handle:
        json.dump(runtime_config, handle, indent=2)
        handle.write("\n")

    aliases = inline_initializer_identities(fp32, inlined)
    gather_nodes = word_embedding_gathers(inlined)
    quantizer = MatMulNBitsQuantizer(
        str(inlined),
        bits=4,
        block_size=128,
        is_symmetric=False,
        nodes_to_include=gather_nodes,
        op_types_to_quantize=("Gather",),
    )
    quantizer.process()
    quantizer.model.save_model_to_file(str(int4_embeddings))

    quantize_dynamic(
        model_input=str(int4_embeddings),
        model_output=str(quantized),
        op_types_to_quantize=["MatMul"],
        weight_type=QuantType.QInt8,
        per_channel=True,
        reduce_range=False,
        extra_options={"DefaultTensorType": 1},
    )
    validation = validate_quantized_model(quantized)
    manifest = {
        "source": {"repo": args.repo, "revision": args.revision},
        "precision": {"word_embeddings": "uint4", "matmul_weights": "qint8"},
        "identity_aliases_inlined": aliases,
        "word_embedding_gather": gather_nodes[0],
        "model_file": quantized.name,
        "model_size_mib": round(quantized.stat().st_size / 1024 / 1024, 3),
        "validation": validation,
    }
    with (output / "quantization_manifest.json").open("w") as handle:
        json.dump(manifest, handle, indent=2)
        handle.write("\n")

    inlined.unlink()
    int4_embeddings.unlink()
    if not args.keep_fp32:
        fp32.unlink()
    print(json.dumps(manifest, indent=2))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--repo", default=DEFAULT_REPO)
    parser.add_argument("--revision", default=DEFAULT_REVISION)
    parser.add_argument("--cache-dir", type=Path, default=None)
    parser.add_argument("--keep-fp32", action="store_true")
    return parser.parse_args()


if __name__ == "__main__":
    export_and_quantize(parse_args())
