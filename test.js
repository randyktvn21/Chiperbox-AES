const assert = require('assert');
const AES128 = require('./aes.js');

const key = AES128.hexToBlock('000102030405060708090a0b0c0d0e0f', 'key');
const plaintext = AES128.hexToBlock('00112233445566778899aabbccddeeff', 'plaintext');
const expectedCipher = '69c4e0d86a7b0430d8cdb78070b4c55a';

const encTrace = AES128.encryptBlockTrace(plaintext, key);
assert.strictEqual(encTrace.outputHex, expectedCipher, 'AES-128 encryption vector failed');

const decTrace = AES128.decryptBlockTrace(AES128.hexToBlock(expectedCipher, 'ciphertext'), key);
assert.strictEqual(decTrace.outputHex, '00112233445566778899aabbccddeeff', 'AES-128 decryption vector failed');

assert.strictEqual(AES128.gfMul(0x57, 0x13), 0xfe, 'GF(2^8) multiplication example failed');
assert.strictEqual(AES128.keyExpansion(key).words.length, 44, 'AES-128 key expansion must have 44 words');
assert.strictEqual(AES128.bytesToHex(AES128.keyExpansion(key).roundKeys[10]), '13111d7fe3944a17f307a78b4d2b30c5', 'Round key 10 mismatch');

for (let i = 0; i < 32; i++) {
  const block = Array.from({ length: 16 }, (_, j) => (i * 17 + j * 29) & 0xff);
  const k = Array.from({ length: 16 }, (_, j) => (i * 31 + j * 7) & 0xff);
  const c = AES128.encryptBlock(block, k);
  const p = AES128.decryptBlock(c, k);
  assert.deepStrictEqual(p, block, `roundtrip failed at sample ${i}`);
}

console.log('All AES-128 tests passed.');
