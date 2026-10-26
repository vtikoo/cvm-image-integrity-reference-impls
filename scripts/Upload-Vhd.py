import email.utils
import hashlib
import json
import os
import pathlib
import time
import urllib.error
import urllib.parse
import urllib.request

work = pathlib.Path("/var/tmp/canonical-build")
vhd = work / "canonical-tmpfs.vhd"
root_hash = (work / "evidence/root-hash.txt").read_text().strip()
url = os.environ["POC_BLOB_URL"]
assert url.startswith("https://") and "?" not in url
size = vhd.stat().st_size
assert size % 512 == 0
digest = hashlib.sha256()
with vhd.open("rb") as file:
    while data := file.read(16 * 1024 * 1024):
        digest.update(data)
sha256 = digest.hexdigest()
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
token = None
expires = 0


def request(method, data=None, headers=None, allow_not_found=False):
    global token, expires
    for attempt in range(10):
        if time.time() + 300 >= expires:
            imds_url = (
                "http://169.254.169.254/metadata/identity/oauth2/token"
                "?api-version=2018-02-01&resource=https%3A%2F%2Fstorage.azure.com%2F"
            )
            with opener.open(
                urllib.request.Request(imds_url, headers={"Metadata": "true"}), timeout=30
            ) as response:
                identity = json.load(response)
            token = identity["access_token"]
            expires = int(identity["expires_on"])
        all_headers = {
            "Authorization": f"Bearer {token}",
            "x-ms-version": "2021-12-02",
            "x-ms-date": email.utils.formatdate(usegmt=True),
        }
        all_headers.update(headers or {})
        try:
            with opener.open(
                urllib.request.Request(url, data=data, headers=all_headers, method=method),
                timeout=120,
            ) as response:
                return response.status, response.headers, response.read()
        except urllib.error.HTTPError as error:
            code = error.headers.get("x-ms-error-code", "")
            if allow_not_found and error.code == 404:
                return 404, error.headers, error.read()
            if error.code in (403, 429, 500, 503) and attempt < 9:
                print(f"Storage request retry {attempt + 1}: HTTP {error.code} {code}", flush=True)
                time.sleep(20)
                continue
            raise RuntimeError(f"Storage {method} failed: HTTP {error.code} {code}") from error
    raise RuntimeError("Storage retry loop exhausted")


status, properties, _ = request("HEAD", allow_not_found=True)
if status == 404:
    request(
        "PUT",
        b"",
        {
            "x-ms-blob-type": "PageBlob",
            "x-ms-blob-content-length": str(size),
            "x-ms-meta-vhd_sha256": sha256,
            "x-ms-meta-root_hash": root_hash,
            "If-None-Match": "*",
        },
    )
else:
    assert properties.get("x-ms-blob-type") == "PageBlob"
    assert int(properties["Content-Length"]) == size
    assert properties.get("x-ms-meta-vhd_sha256") == sha256
    assert properties.get("x-ms-meta-root_hash") == root_hash
uploaded = 0
with vhd.open("rb") as file:
    offset = 0
    while data := file.read(4 * 1024 * 1024):
        if data.strip(b"\0"):
            # Page updates use a query parameter, never a SAS credential.
            base_url = url
            url = base_url + "?comp=page"
            try:
                request(
                    "PUT",
                    data,
                    {
                        "x-ms-page-write": "update",
                        "x-ms-range": f"bytes={offset}-{offset + len(data) - 1}",
                        "Content-Type": "application/octet-stream",
                    },
                )
            finally:
                url = base_url
            uploaded += len(data)
        offset += len(data)
assert offset == size
_, properties, _ = request("HEAD")
assert int(properties["Content-Length"]) == size
_, _, footer = request("GET", headers={"Range": f"bytes={size - 512}-{size - 1}"})
assert footer[:8] == b"conectix" and len(footer) == 512
result = {
    "url": url,
    "size": size,
    "uploaded_nonzero_page_bytes": uploaded,
    "sha256": sha256,
    "root_hash": root_hash,
    "authentication": "system-assigned managed identity; container-scoped data contributor",
}
(work / "evidence/blob-upload.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result))
print("VHD_UPLOAD_PASSED")
