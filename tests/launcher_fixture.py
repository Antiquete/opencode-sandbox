"""Shared recording-runtime fixture for launcher tests."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def make_fake_runtime(directory, name):
    runtime = directory / name
    runtime.write_text((ROOT / "tests" / "fake_runtime.py").read_text())
    runtime.chmod(0o755)
    return runtime
