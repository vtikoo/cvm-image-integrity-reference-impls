#!/usr/bin/env python3
"""Builder-only page-blob upload with managed identity and full byte readback."""

import email.utils
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def upload(path, url, expected, root_hash, record=None):
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == "https" and parsed.hostname.endswith(".blob.core.windows.net")
            and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment,
            "Expected an Azure blob HTTPS URL without credentials")
    require(re.fullmatch(r"[0-9a-f]{64}", expected) and re.fullmatch(r"[0-9a-f]{64}", root_hash),
            "Expected verified build hashes")
    size = path.stat().st_size
    require(size > 512 and size % 512 == 0, "VHD is not page aligned")
    h = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(16 * 1024 * 1024):
            h.update(chunk)
        stream.seek(-512, 2)
        footer = bytearray(stream.read(512))
    require(h.hexdigest() == expected, "Local VHD changed after offline validation")
    virtual_size = struct.unpack_from(">Q", footer, 48)[0]
    checksum = struct.unpack_from(">I", footer, 64)[0]
    footer[64:68] = bytes(4)
    require(footer[:8] == b"conectix" and struct.unpack_from(">I", footer, 60)[0] == 2
            and virtual_size + 512 == size and virtual_size % (1024 * 1024) == 0
            and checksum == (~sum(footer) & 0xffffffff), "VHD fixed footer validation failed")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    token, expires = None, 0

    def request(method, suffix="", data=None, headers=None):
        nonlocal token, expires
        for attempt in range(18):
            if time.time() + 300 >= expires:
                imds = ("http://169.254.169.254/metadata/identity/oauth2/token"
                        "?api-version=2018-02-01&resource=https%3A%2F%2Fstorage.azure.com%2F")
                with opener.open(urllib.request.Request(imds, headers={"Metadata": "true"}), timeout=30) as response:
                    identity = json.load(response)
                token, expires = identity["access_token"], int(identity["expires_on"])
            all_headers = {"Authorization": "Bearer " + token, "x-ms-version": "2021-12-02",
                           "x-ms-date": email.utils.formatdate(usegmt=True)}
            all_headers.update(headers or {})
            try:
                with opener.open(urllib.request.Request(url + suffix, data=data, headers=all_headers, method=method),
                                 timeout=180) as response:
                    return response.status, response.headers, response.read()
            except urllib.error.HTTPError as error:
                # Do not log request/response bodies or the managed-identity token.
                if error.code in (403, 429, 500, 502, 503, 504) and attempt < 17:
                    time.sleep(20)
                    continue
                raise RuntimeError(f"Managed-identity blob {method} failed (HTTP {error.code})") from None
        raise RuntimeError("Managed-identity storage retries exhausted")

    request("PUT", data=b"", headers={
        "x-ms-blob-type": "PageBlob", "x-ms-blob-content-length": str(size),
        "x-ms-meta-vhd_sha256": expected, "x-ms-meta-root_hash": root_hash, "If-None-Match": "*",
    })
    with path.open("rb") as stream:
        offset = 0
        while chunk := stream.read(4 * 1024 * 1024):
            if chunk.strip(b"\0"):
                request("PUT", "?comp=page", data=chunk, headers={
                    "x-ms-page-write": "update", "x-ms-range": f"bytes={offset}-{offset + len(chunk) - 1}",
                    "Content-Type": "application/octet-stream",
                })
            offset += len(chunk)
    _, properties, _ = request("HEAD")
    require(properties.get("x-ms-blob-type") == "PageBlob" and int(properties["Content-Length"]) == size
            and properties.get("x-ms-meta-vhd_sha256") == expected
            and properties.get("x-ms-meta-root_hash") == root_hash, "Blob properties differ from verified build")
    # Independently read every byte, not merely metadata supplied by this uploader.
    readback = hashlib.sha256()
    etag = properties["ETag"]
    for offset in range(0, size, 4 * 1024 * 1024):
        end = min(offset + 4 * 1024 * 1024, size) - 1
        _, _, chunk = request("GET", headers={"Range": f"bytes={offset}-{end}", "If-Match": etag})
        require(len(chunk) == end - offset + 1, "Truncated page blob readback")
        readback.update(chunk)
    require(readback.hexdigest() == expected, "Uploaded page blob SHA256 mismatch")
    result = {"url": url, "size": size, "sha256": expected, "readbackSha256": readback.hexdigest(),
              "rootHash": root_hash, "authentication": "system-assigned managed identity; container-scoped role"}
    record = Path("/var/lib/cvm-dracut/upload.json") if record is None else record
    with record.open("x") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print("DRACUT_VHD_UPLOAD_PASSED")
    return result


if __name__ == "__main__":
    os.umask(0o077)
    upload(Path(sys.argv[1]), *sys.argv[2:])
