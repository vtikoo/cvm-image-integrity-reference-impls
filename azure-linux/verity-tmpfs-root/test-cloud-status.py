"""Exercise the actual guest check's narrow cloud-init warning policy."""
import copy
import json
import pathlib
import subprocess
import sys
import tempfile

source = pathlib.Path(__file__).with_name("guest-check.sh").read_text()
validator = source.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
warning = (
    "Unable to find provisioning media, falling back to IMDS metadata. "
    "Be aware that IMDS metadata does not support admin passwords or "
    "custom-data (user-data only)."
)
healthy = {
    "status": "done",
    "errors": [],
    "recoverable_errors": {},
    "detail": "DataSourceAzure [seed=/dev/sr0]",
}
imds = dict(
    healthy,
    detail="DataSourceAzure [seed=IMDS]",
    recoverable_errors={"WARNING": [warning]},
)
unexpected = copy.deepcopy(imds)
unexpected["recoverable_errors"]["WARNING"].append("Unexpected provisioning failure")
fatal = dict(healthy, errors=["Fatal provisioning failure"])
running = dict(healthy, status="running")
for name, mode, code, status, succeeds in [
    ("healthy first provision", "write", "0", healthy, True),
    ("explicit reboot IMDS warning", "reset", "2", imds, True),
    ("warning on first provision", "write", "2", imds, False),
    ("additional warning", "reset", "2", unexpected, False),
    ("fatal error", "reset", "1", fatal, False),
    ("incomplete provision", "reset", "0", running, False),
]:
    with tempfile.NamedTemporaryFile(mode="w") as stream:
        json.dump(status, stream)
        stream.flush()
        result = subprocess.run(
            [sys.executable, "-", mode, code, stream.name],
            input=validator,
            text=True,
            capture_output=True,
        )
    assert (result.returncode == 0) == succeeds, (name, result.stderr)
    print("PASS:", name)
print("CLOUD_STATUS_ACCEPTANCE_POLICY_OK")
