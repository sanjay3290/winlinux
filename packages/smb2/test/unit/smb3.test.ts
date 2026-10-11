// SMB 3.x crypto against published vectors: the Microsoft Open
// Specifications blog (preauth hash chain, SP800-108 keys for 3.0 and
// 3.1.1, AES-CMAC signature of a real final SESSION_SETUP response,
// AES-128-GCM and AES-128-CCM transforms), RFC 4493 (AES-CMAC), and an
// OpenSSL GMAC oracle for AES-GMAC signing.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  Cipher,
  NonceSource,
  PREAUTH_INITIAL,
  SigningAlgorithm,
  aesCmac,
  appendNegotiateContexts,
  computeSignature3,
  decryptMessage,
  deriveKeys,
  dialectName,
  encryptMessage,
  gmacNonce,
  isTransformed,
  parseNegotiateContexts,
  preauthUpdate,
  signMessage3,
  verifySignature3,
} from "../../src/smb3.js";
import { ccm, gcm, smb30 } from "../fixtures/smb3-vectors.js";

const hex = (s: string) => Buffer.from(s, "hex");

describe("AES-CMAC (RFC 4493 section 4)", () => {
  const key = hex("2b7e151628aed2a6abf7158809cf4f3c");
  const m = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
  for (const [len, mac] of [
    [0, "bb1d6929e95937287fa37d129b756746"],
    [16, "070a16b46b4d4144f79bdd9dd04a287c"],
    [40, "dfa66747de9ae63030ca32611497c827"],
    [64, "51f0bebf7e3b9d92fc49741779363cfe"],
  ] as const) {
    it(`${len}-byte message`, () => {
      assert.equal(aesCmac(key, hex(m.slice(0, len * 2))).toString("hex"), mac);
    });
  }
});

describe("SMB 3.1.1 negotiate contexts and preauth integrity (Microsoft vector A.1)", () => {
  it("builds the published NEGOTIATE request byte for byte", () => {
    for (const v of [gcm, ccm]) {
      const full = hex(v.negotiateRequest);
      const base = Buffer.from(full.subarray(0, 64 + 36 + 10)); // header, fixed body, five dialects
      base.fill(0, 64 + 28, 64 + 36); // ClientStartTime slot
      const salt = full.subarray(112 + 8 + 6, 112 + 8 + 6 + 32);
      const ciphers = v === gcm ? [Cipher.Aes128Gcm, Cipher.Aes128Ccm] : [Cipher.Aes128Ccm, Cipher.Aes128Gcm];
      const built = appendNegotiateContexts(base, { salt, ciphers, signing: [] });
      assert.equal(built.toString("hex"), v.negotiateRequest);
    }
  });

  it("adds a signing context, 8-byte aligned, when signing algorithms are offered", () => {
    const base = Buffer.alloc(64 + 36 + 10);
    const built = appendNegotiateContexts(base, {
      salt: Buffer.alloc(32, 7),
      ciphers: [Cipher.Aes128Gcm, Cipher.Aes128Ccm],
      signing: [SigningAlgorithm.AesGmac, SigningAlgorithm.AesCmac],
    });
    assert.equal(built.readUInt32LE(64 + 28), 112);
    assert.equal(built.readUInt16LE(64 + 32), 3);
    // preauth (8 + 38) ends at 158, pad to 160; encryption (8 + 6) ends at 174, pad to 176.
    assert.equal(built.readUInt16LE(160), 0x0002);
    assert.equal(built.readUInt16LE(176), 0x0008);
    assert.equal(built.subarray(176 + 8).toString("hex"), "020002000100");
  });

  it("parses the server's choices from the published responses", () => {
    assert.deepEqual(parseNegotiateContexts(hex(gcm.negotiateResponse)), { cipher: Cipher.Aes128Gcm, hashAlgorithm: 1 });
    assert.deepEqual(parseNegotiateContexts(hex(ccm.negotiateResponse)), { cipher: Cipher.Aes128Ccm, hashAlgorithm: 1 });
  });

  it("chains SHA-512 over NEGOTIATE and SESSION_SETUP exactly as published", () => {
    let h = preauthUpdate(PREAUTH_INITIAL, hex(gcm.negotiateRequest));
    assert.equal(h.toString("hex"), gcm.hashAfterNegotiateRequest);
    h = preauthUpdate(h, hex(gcm.negotiateResponse));
    assert.equal(h.toString("hex"), gcm.hashAfterNegotiateResponse);
    h = preauthUpdate(h, hex(gcm.setupRequest1));
    assert.equal(h.toString("hex"), gcm.hashAfterSetupRequest1);
    h = preauthUpdate(h, hex(gcm.setupResponse1)); // STATUS_MORE_PROCESSING_REQUIRED
    assert.equal(h.toString("hex"), gcm.hashAfterSetupResponse1);
    h = preauthUpdate(h, hex(gcm.setupRequest2));
    assert.equal(h.toString("hex"), gcm.hashAfterSetupRequest2);
    // The final (STATUS_SUCCESS) response is not hashed.
  });
});

describe("SP800-108 key derivation", () => {
  it("SMB 3.1.1 keys from the session key and the preauth hash (GCM and CCM vectors)", () => {
    for (const v of [gcm, ccm]) {
      const keys = deriveKeys(0x0311, hex(v.sessionKey), hex(v.hashAfterSetupRequest2));
      assert.equal(keys.signingKey.toString("hex"), v.signingKey);
      assert.equal(keys.encryptionKey.toString("hex"), v.encryptionKey);
      assert.equal(keys.decryptionKey.toString("hex"), v.decryptionKey);
    }
    assert.throws(() => deriveKeys(0x0311, hex(gcm.sessionKey)), /pre-authentication hash/);
  });

  it("SMB 3.0 / 3.0.2 keys from constant labels", () => {
    for (const dialect of [0x0300, 0x0302]) {
      const keys = deriveKeys(dialect, hex(smb30.sessionKey));
      assert.equal(keys.signingKey.toString("hex"), smb30.signingKey);
      assert.equal(keys.encryptionKey.toString("hex"), smb30.encryptionKey);
      assert.equal(keys.decryptionKey.toString("hex"), smb30.decryptionKey);
    }
  });
});

describe("SMB 3.x signing", () => {
  it("AES-CMAC verifies the server's signed final SESSION_SETUP responses", () => {
    for (const v of [gcm, ccm]) {
      const message = hex(v.setupResponse2);
      assert.ok(verifySignature3(message, SigningAlgorithm.AesCmac, hex(v.signingKey)));
      const tampered = Buffer.from(message);
      tampered[tampered.length - 1] ^= 1;
      assert.ok(!verifySignature3(tampered, SigningAlgorithm.AesCmac, hex(v.signingKey)));
      assert.ok(!verifySignature3(message, SigningAlgorithm.AesGmac, hex(v.signingKey)));
    }
  });

  it("AES-GMAC matches an OpenSSL GMAC oracle; the nonce carries the response and CANCEL bits", () => {
    const key = hex(gcm.signingKey);
    const cancel = hex("fe534d4240000100000000000c00010002000000000000000500000000000000fffe00000100000025000000001000000000000000000000000000000000000004000000");
    for (const [message, nonce, tag] of [
      [hex(gcm.writePlain), "050000000000000000000000", "32e8c1c0d814298bb009899649850d92"],
      [hex(gcm.responsePlain), "050000000000000001000000", "83196769b1e9e7fa0aa4ac18035c2192"],
      [cancel, "050000000000000002000000", "8657ef1747f1b00dededf228188638d5"],
    ] as const) {
      assert.equal(gmacNonce(message).toString("hex"), nonce);
      assert.equal(computeSignature3(message, SigningAlgorithm.AesGmac, key).toString("hex"), tag);
    }
  });

  it("signMessage3 sets the Signed flag and signs over it; verify round-trips for each algorithm", () => {
    const message = hex(gcm.writePlain);
    message.writeUInt32LE(message.readUInt32LE(16) & ~0x8, 16); // the published packet already carries the flag
    for (const alg of [SigningAlgorithm.AesCmac, SigningAlgorithm.AesGmac, SigningAlgorithm.HmacSha256]) {
      const signed = signMessage3(message, alg, hex(gcm.signingKey));
      assert.equal(signed.readUInt32LE(16) & 0x8, 0x8);
      assert.ok(verifySignature3(signed, alg, hex(gcm.signingKey)));
      assert.equal(message.readUInt32LE(16) & 0x8, 0, "input untouched");
    }
  });
});

describe("TRANSFORM_HEADER encryption", () => {
  for (const [name, v, cipher, nonceBytes] of [
    ["SMB 3.1.1 AES-128-GCM", gcm, Cipher.Aes128Gcm, 12],
    ["SMB 3.1.1 AES-128-CCM", ccm, Cipher.Aes128Ccm, 11],
    ["SMB 3.0 AES-128-CCM", smb30, Cipher.Aes128Ccm, 16],
  ] as const) {
    it(`${name}: encrypts the WRITE request and decrypts the response as published`, () => {
      const transformed = hex(v.writeTransformed);
      const sessionId = transformed.subarray(44, 52);
      // The 3.0 vector filled the whole 16-byte Nonce field; it is in the AAD.
      const nonce = nonceBytes === 16 ? transformed.subarray(20, 36) : hex(v.writeNonce);
      const out = encryptMessage(hex(v.writePlain), sessionId, cipher, hex(v.encryptionKey), nonce);
      assert.equal(out.toString("hex"), v.writeTransformed);
      assert.ok(isTransformed(out));

      const decrypted = decryptMessage(hex(v.responseTransformed), cipher, hex(v.decryptionKey));
      assert.equal(decrypted.message.toString("hex"), v.responsePlain);
      assert.ok(decrypted.sessionId.equals(sessionId));
    });
  }

  it("rejects a tampered byte, a wrong key and a wrong cipher", () => {
    const frame = hex(gcm.responseTransformed);
    for (const offset of [5, 30, 60, frame.length - 1]) {
      const bad = Buffer.from(frame);
      bad[offset] ^= 0x01;
      assert.throws(() => decryptMessage(bad, Cipher.Aes128Gcm, hex(gcm.decryptionKey)), /failed authentication|size mismatch/);
    }
    assert.throws(() => decryptMessage(frame, Cipher.Aes128Gcm, hex(gcm.encryptionKey)), /failed authentication/);
    assert.throws(() => decryptMessage(frame, Cipher.Aes128Ccm, hex(gcm.decryptionKey)), /failed authentication/);
    assert.throws(() => decryptMessage(hex(gcm.responsePlain), Cipher.Aes128Gcm, hex(gcm.decryptionKey)), /not an SMB2 TRANSFORM_HEADER/);
  });

  it("nonces never repeat on one connection and have the cipher's length", () => {
    const source = new NonceSource();
    const seen = new Set<string>();
    for (let i = 0; i < 1000; i++) {
      const n = source.next(i % 2 ? Cipher.Aes128Gcm : Cipher.Aes128Ccm);
      assert.equal(n.length, i % 2 ? 12 : 11);
      const tail = n.subarray(-8).toString("hex");
      assert.ok(!seen.has(tail));
      seen.add(tail);
    }
  });

  it("names dialects", () => {
    assert.deepEqual([0x0202, 0x0210, 0x0300, 0x0302, 0x0311, 0x02ff].map(dialectName), ["2.0.2", "2.1", "3.0", "3.0.2", "3.1.1", "0x02ff"]);
  });
});
