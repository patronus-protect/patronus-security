#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
revision=e3749b44a0f85268347cdfb6818f4ef39e8ff203
model="wolf_defender_small_${revision}_fp16_256"
base="https://huggingface.co/patronus-studio/wolf-defender-prompt-injection-small/resolve/${revision}"
triton_image="nvcr.io/nvidia/tritonserver@sha256:9185ba5b33d2c85c9204b208957b4bbfc6b2b89066efc9192e0f60c2ab58cec0"
mkdir -p source-wolf "wolf-models/${model}/1"
if [[ ! -f source-wolf/model_fp16.onnx ]]; then
  curl -fLsS --retry 2 "${base}/onnx/onnx_fp16/model_fp16.onnx" -o source-wolf/model_fp16.onnx
fi
if [[ ! -f source-wolf/tokenizer.json ]]; then
  curl -fLsS --retry 2 "${base}/tokenizer.json" -o source-wolf/tokenizer.json
fi
printf '%s  %s\n' \
  'b0d318faa65e504db3a5f94d9367c4a6ae4141f007e749636dd3102fc17709ab' source-wolf/model_fp16.onnx \
  '609d8f4c067cd3950f88594c5a802616cea245823836ef5848ee4fc40aab5b6f' source-wolf/tokenizer.json \
  | sha256sum -c -
.venv/bin/python export_wolf_output.py
docker run --rm --gpus all -v "$PWD:/work" \
  --entrypoint /usr/src/tensorrt/bin/trtexec "${triton_image}" \
  --onnx=/work/source-wolf/model_triton.onnx \
  --saveEngine="/work/wolf-models/${model}/1/model.plan" \
  --minShapes=input_ids:1x256,attention_mask:1x256 \
  --optShapes=input_ids:16x256,attention_mask:16x256 \
  --maxShapes=input_ids:16x256,attention_mask:16x256 --skipInference
cp wolf-config.pbtxt "wolf-models/${model}/config.pbtxt"
sha256sum source-wolf/model_fp16.onnx source-wolf/model_triton.onnx "wolf-models/${model}/1/model.plan" > wolf-artifact-sha256.txt
