"""Exercise the real Python/Core/ORT boundary in bounded child processes."""
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


SCRIPT = r'''
import sys
import time
from concurrent.futures import ThreadPoolExecutor, wait
from patronus_ark_core import Scanner, ScanControl, ScannerBusyError, CancelledError

scanner = Scanner({
    "categories": ["injection"],
    "models": {"native:injection_l1": False},
    "wolf": {"bundle_dir": sys.argv[1], "threshold": 0.8,
             "precision": "fp16", "backend": "cpu"},
})
mode = sys.argv[2]
control = ScanControl(timeout_ms=5000 if mode == "cancel" else 1000)
with ThreadPoolExecutor(max_workers=1) as pool:
    future = pool.submit(scanner.scan, " a", pii=False, dlp=False, control=control)
    # Allow the worker to acquire the scanner before probing its actual state.
    time.sleep(0.01)
    observed_busy = False
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline and not future.done():
        try:
            scanner.scan("", pii=False, dlp=False)
        except ScannerBusyError:
            observed_busy = True
            break
        time.sleep(0.001)
    assert observed_busy, "same scanner must reject concurrent access while the GIL is released"
    assert not future.done()
    if mode == "cancel":
        time.sleep(0.03)
        control.cancel()
    done, _ = wait([future], timeout=3)
    assert future in done, "Core must finish cancelled/deadline work before the host wait expires"
    try:
        future.result()
    except (CancelledError if mode == "cancel" else TimeoutError):
        pass
    else:
        raise AssertionError("active work must not return a partial successful report")
assert scanner.scan("", pii=False, dlp=False)["wolf"]["document_logit"] == 0.0
'''


@pytest.mark.parametrize("mode", ["cancel", "deadline"])
def test_same_scanner_busy_active_cancellation_and_reuse(tmp_path, mode):
    fixtures = Path(__file__).resolve().parents[2] / "tests/fixtures"
    shutil.copyfile(fixtures / "wolf_cancellable.onnx", tmp_path / "model_fp16.onnx")
    shutil.copyfile(fixtures / "tokenizer.mmbpe", tmp_path / "tokenizer.mmbpe")
    (tmp_path / "config.json").write_text(json.dumps({"num_labels": 1}))
    child = subprocess.run(
        [sys.executable, "-c", SCRIPT, str(tmp_path), mode],
        capture_output=True, text=True, timeout=30,
    )
    assert child.returncode == 0, child.stdout + child.stderr
