import base64
import gzip
import hashlib
import json
import pathlib
import re
import sys

path = pathlib.Path(base64.b64decode(sys.argv[1], validate=True).decode())
index = int(sys.argv[2])
data = path.read_bytes()
if re.search(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----", data):
    raise ValueError("Private signing material must stay on the helper.")
encoded = base64.b64encode(gzip.compress(data, mtime=0)).decode()
chunks = (len(encoded) + 2999) // 3000
if not 0 <= index < chunks:
    raise ValueError("Artifact chunk index is outside the available range.")
print(json.dumps(dict(index=index, chunks=chunks, sha256=hashlib.sha256(data).hexdigest(),
                     payload=encoded[index * 3000:(index + 1) * 3000])))
print("MANAGED_ARTIFACT_CHUNK_READY")
