#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
revision=6cfcbd93d7fc6f5e1658f80afa38f73891b91693
model="gliner_small_${revision}_fp16"
base="https://huggingface.co/patronus-studio/gliner_small-v2.5-edge/resolve/${revision}"
mkdir -p source-gliner "gliner-models/${model}/1"
if [[ ! -f source-gliner/model_fp16.onnx ]]; then
  curl -fLsS --retry 2 "${base}/onnx/fp16/model_fp16.onnx" -o source-gliner/model_fp16.onnx
fi
printf '%s  %s\n' \
  '48e921e2c1eb7daeac3b643bf238f02f93d8226bd388cc2ba1bcf835b088eeaa' source-gliner/model_fp16.onnx \
  | sha256sum -c -
cp source-gliner/model_fp16.onnx "gliner-models/${model}/1/model.onnx"
cp gliner-config.pbtxt "gliner-models/${model}/config.pbtxt"
