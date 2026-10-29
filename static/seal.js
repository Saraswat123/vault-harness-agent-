// Encrypts a small JSON object to the enclave's public key, in the USER'S browser. Same format as vault_harness/enclave.py seal():
// X25519 ECDH -> HKDF-SHA256 (info = label | epk | enclave pub, zero salt) -> AES-256-GCM (96-bit nonce, aad bound to the card id / payment nonce).
const hex2b = (h) => Uint8Array.from(h.match(/../g).map((x) => parseInt(x, 16)));
const b2hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");

export async function seal(pubHex, obj, aadStr) {
  const pub = hex2b(pubHex);
  const eph = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const epk = new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey));
  const srv = await crypto.subtle.importKey("raw", pub, { name: "X25519" }, false, []);
  const shared = await crypto.subtle.deriveBits({ name: "X25519", public: srv }, eph.privateKey, 256);
  const info = new Uint8Array([...new TextEncoder().encode("vault-harness/seal/v1"), ...epk, ...pub]);
  const hk = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info }, hk, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const aad = new TextEncoder().encode(aadStr);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 }, key, new TextEncoder().encode(JSON.stringify(obj)));
  return { epk: b2hex(epk), nonce: b2hex(nonce), ct: b2hex(ct), aad: b2hex(aad) };
}
