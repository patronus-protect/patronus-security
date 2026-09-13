#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
revision=30ea449339d1075a31fcffa9199ebee4f2cfaf9a
model="lion_warden_${revision}_fp16_256"
base="https://huggingface.co/patronus-studio/lion-warden-ai-security-classifier/resolve/${revision}"
triton_image="nvcr.io/nvidia/tritonserver@sha256:9185ba5b33d2c85c9204b208957b4bbfc6b2b89066efc9192e0f60c2ab58cec0"
mkdir -p source "models/${model}/1"
for file in config.json tokenizer.json; do
  curl -fLsS --retry 2 "${base}/${file}" -o "source/${file}"
done
curl -fLsS --retry 2 "${base}/onnx/onnx_fp16/model_fp16.onnx" -o source/model_fp16.onnx
printf '%s  %s\n' \
  '1a0d7d997fa51a46177cfe5e8d6652a77f68c0939be92715477bdafb81dbd920' source/config.json \
  '609d8f4c067cd3950f88594c5a802616cea245823836ef5848ee4fc40aab5b6f' source/tokenizer.json \
  'c29c8aff3db3efb3da923d54da6588a51bc07023d31869c7d1363704d00ca894' source/model_fp16.onnx \
  | sha256sum -c -
docker pull "${triton_image}"
python3 -m venv .venv
.venv/bin/pip install -q onnx==1.22.0
.venv/bin/python export_output.py
# TensorRT 11 preserves the explicit precision of the FP16 ONNX graph.
docker run --rm --gpus all -v "$PWD:/work" \
  --entrypoint /usr/src/tensorrt/bin/trtexec "${triton_image}" \
  --onnx=/work/source/model_triton.onnx \
  --saveEngine="/work/models/${model}/1/model.plan" \
  --minShapes=input_ids:1x256,attention_mask:1x256 \
  --optShapes=input_ids:16x256,attention_mask:16x256 \
  --maxShapes=input_ids:16x256,attention_mask:16x256 --skipInference
cp config.pbtxt "models/${model}/config.pbtxt"
sha256sum source/model_fp16.onnx source/tokenizer.json "models/${model}/1/model.plan" > artifact-sha256.txt
