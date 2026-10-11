// Independent signing oracle: HMAC-SHA256 (first 16 bytes) over the golden
// treeConnect packet with the signature field zeroed, computed with CPython.
// Reproduce: python3 -c "import hmac,hashlib;key=bytes(range(16));
// msg=bytes.fromhex(<treeConnect from golden-packets.ts>);
// print(hmac.new(key,msg[:48]+bytes(16)+msg[64:],hashlib.sha256).digest()[:16].hex())"
export const oracleKey = "000102030405060708090a0b0c0d0e0f";
export const oracleSignature = "104bfe0accfc9fb3d61b313c0ed65cbb";
