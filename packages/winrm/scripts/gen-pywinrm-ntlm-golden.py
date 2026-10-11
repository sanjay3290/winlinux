#!/usr/bin/env python3
"""Generate the NTLM-encrypted WinRM request golden fixture.

Source of truth: pywinrm winrm/encryption.py
  https://github.com/diyan/pywinrm/blob/fbb05e87dc8c7ad79bc5dc1d334c39f28bc80b73/winrm/encryption.py
  (last commit touching the file: fbb05e8, 2024-06-06)

The framing below reproduces these pywinrm methods byte for byte:
  Encryption._build_ntlm_message   -> struct.pack("<i", len(signature)) + signature + sealed_message
  Encryption._encrypt_message      -> the two MIME parts with tab-indented headers
  Encryption.prepare_encrypted_request -> appends MIME_BOUNDARY + b"--\\r\\n"
                                          and builds the Content-Type header

pywinrm gets (sealed_message, signature) from ntlm-auth/pyspnego
session_security.wrap(). This script computes the same pair with the
MS-NLMP 3.4.4.2 NTLMv2 SEAL (extended session security, 128-bit, key
exchange), so the payload has the real NTLM layout. The key is fixed, so
the output is deterministic.

Run from the repo root:
  python3 packages/winrm/scripts/gen-pywinrm-ntlm-golden.py
Stdlib only. Writes to packages/winrm/test/fixtures/golden/.
"""

import hashlib
import hmac
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
GOLDEN = os.path.join(HERE, "..", "test", "fixtures", "golden")

# ---- MS-NLMP 3.4.4.2 / 3.4.5.2 / 3.4.5.3 (client-to-server direction) ----

EXPORTED_SESSION_KEY = bytes(range(0x00, 0x10))  # fixed, test-only
SEQ_NUM = 0


def rc4_init(key):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    return {"s": s, "i": 0, "j": 0}


def rc4_update(state, data):
    s, i, j = state["s"], state["i"], state["j"]
    out = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out.append(byte ^ s[(s[i] + s[j]) % 256])
    state["i"], state["j"] = i, j
    return bytes(out)


def ntlm_wrap(message):
    """Return (sealed_message, signature), like session_security.wrap()."""
    sign_key = hashlib.md5(
        EXPORTED_SESSION_KEY + b"session key to client-to-server signing key magic constant\x00"
    ).digest()
    seal_key = hashlib.md5(
        EXPORTED_SESSION_KEY + b"session key to client-to-server sealing key magic constant\x00"
    ).digest()
    handle = rc4_init(seal_key)
    seq = struct.pack("<I", SEQ_NUM)
    sealed_message = rc4_update(handle, message)
    checksum = hmac.new(sign_key, seq + message, hashlib.md5).digest()[:8]
    checksum = rc4_update(handle, checksum)  # NTLMSSP_NEGOTIATE_KEY_EXCH
    signature = struct.pack("<I", 1) + checksum + seq
    return sealed_message, signature


# ---- pywinrm winrm/encryption.py (NTLM path), reproduced ----

MIME_BOUNDARY = b"--Encrypted Boundary"
PROTOCOL_STRING = b"application/HTTP-SPNEGO-session-encrypted"  # protocol == "ntlm"


def _build_ntlm_message(message):
    sealed_message, signature = ntlm_wrap(message)
    signature_length = struct.pack("<i", len(signature))
    return signature_length + signature + sealed_message


def _encrypt_message(message):
    message_length = str(len(message)).encode()
    encrypted_stream = _build_ntlm_message(message)
    return (
        MIME_BOUNDARY + b"\r\n"
        b"\tContent-Type: " + PROTOCOL_STRING + b"\r\n"
        b"\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length=" + message_length + b"\r\n"
        + MIME_BOUNDARY + b"\r\n"
        b"\tContent-Type: application/octet-stream\r\n" + encrypted_stream
    )


def prepare_encrypted_request_body(message):
    return _encrypt_message(message) + MIME_BOUNDARY + b"--\r\n"


def content_type():
    return '{0};protocol="{1}";boundary="Encrypted Boundary"'.format(
        "multipart/encrypted", PROTOCOL_STRING.decode()
    )


def main():
    with open(os.path.join(GOLDEN, "create-shell.xml"), "rb") as f:
        soap = f.read()
    sealed_message, signature = ntlm_wrap(soap)
    # What an NTLM SecurityContext.wrap() returns in this repo: signature || sealed.
    with open(os.path.join(GOLDEN, "pywinrm-ntlm-wrap-output.bin"), "wb") as f:
        f.write(signature + sealed_message)
    with open(os.path.join(GOLDEN, "pywinrm-ntlm-encrypted-request.bin"), "wb") as f:
        f.write(prepare_encrypted_request_body(soap))
    with open(os.path.join(GOLDEN, "pywinrm-ntlm-content-type.txt"), "w") as f:
        f.write(content_type())


if __name__ == "__main__":
    main()
