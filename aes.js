/*
  aes.js
  Pure Vanilla JavaScript AES-128 implementation for one 128-bit block.
  No CryptoJS, no Web Crypto API, no third-party cryptographic library.

  State convention follows FIPS 197:
  s[r][c] = input[r + 4*c], for 0 <= r < 4 and 0 <= c < 4.
*/
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  root.AES128 = api;
})(typeof globalThis !== "undefined" ? globalThis : window, function () {
  "use strict";

  const NB = 4;
  const NK = 4;
  const NR = 10;

  const SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
  ];

  const INV_SBOX = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
  ];

  const RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
  const MIX_MATRIX = [
    [0x02, 0x03, 0x01, 0x01],
    [0x01, 0x02, 0x03, 0x01],
    [0x01, 0x01, 0x02, 0x03],
    [0x03, 0x01, 0x01, 0x02]
  ];
  const INV_MIX_MATRIX = [
    [0x0e, 0x0b, 0x0d, 0x09],
    [0x09, 0x0e, 0x0b, 0x0d],
    [0x0d, 0x09, 0x0e, 0x0b],
    [0x0b, 0x0d, 0x09, 0x0e]
  ];

  function assertByteArray(bytes, expectedLength, label) {
    if (!Array.isArray(bytes) || bytes.length !== expectedLength) {
      throw new Error(`${label} harus berisi ${expectedLength} byte.`);
    }
    for (const b of bytes) {
      if (!Number.isInteger(b) || b < 0 || b > 255) {
        throw new Error(`${label} berisi nilai bukan byte: ${b}.`);
      }
    }
  }

  function hx(byte) {
    return (byte & 0xff).toString(16).padStart(2, "0");
  }

  function bytesToHex(bytes) {
    return bytes.map(hx).join("");
  }

  function wordToHex(word) {
    return bytesToHex(word);
  }

  function cleanHex(str) {
    return String(str).replace(/\s+/g, "").toLowerCase();
  }

  function hexToBytes(hex, label = "Input hex") {
    const h = cleanHex(hex);
    if (!/^[0-9a-f]*$/i.test(h)) throw new Error(`${label} hanya boleh berisi karakter 0-9 dan a-f.`);
    if (h.length % 2 !== 0) throw new Error(`${label} harus memiliki jumlah digit genap.`);
    const out = [];
    for (let i = 0; i < h.length; i += 2) out.push(parseInt(h.slice(i, i + 2), 16));
    return out;
  }

  function hexToBlock(hex, label = "Input") {
    const h = cleanHex(hex);
    if (h.length !== 32) throw new Error(`${label} harus tepat 32 digit hex atau 16 byte.`);
    return hexToBytes(h, label);
  }

  function textToBlock(text) {
    const bytes = Array.from(new TextEncoder().encode(String(text)));
    if (bytes.length > 16) {
      throw new Error("Input teks maksimum 16 byte UTF-8. Karakter non-ASCII dapat memakai lebih dari 1 byte.");
    }
    while (bytes.length < 16) bytes.push(0x00);
    return bytes;
  }

  function blockToText(bytes) {
    assertByteArray(bytes, 16, "Block");
    const trimmed = bytes.slice();
    while (trimmed.length && trimmed[trimmed.length - 1] === 0x00) trimmed.pop();
    return new TextDecoder("utf-8", { fatal: false }).decode(new Uint8Array(trimmed));
  }

  function cloneState(state) {
    return state.map(row => row.slice());
  }

  function bytesToState(bytes) {
    assertByteArray(bytes, 16, "Block");
    const state = [[], [], [], []];
    for (let c = 0; c < 4; c++) {
      for (let r = 0; r < 4; r++) state[r][c] = bytes[r + 4 * c];
    }
    return state;
  }

  function stateToBytes(state) {
    const out = [];
    for (let c = 0; c < 4; c++) {
      for (let r = 0; r < 4; r++) out.push(state[r][c] & 0xff);
    }
    return out;
  }

  function xorWords(a, b) {
    return [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]];
  }

  function rotWord(word) {
    return [word[1], word[2], word[3], word[0]];
  }

  function subWord(word) {
    return word.map(byte => SBOX[byte]);
  }

  function rconWord(round) {
    return [RCON[round], 0x00, 0x00, 0x00];
  }

  /*
    Multiplication in GF(2^8), not ordinary integer multiplication.

    AES interprets each byte as a polynomial over GF(2). Example:
    0x57 = x^6 + x^4 + x^2 + x + 1.

    The product is reduced modulo the irreducible AES polynomial:
    m(x) = x^8 + x^4 + x^3 + x + 1 = 0x11B.

    Implementation detail:
    - Left shift by 1 equals multiplication by x.
    - If the pre-shift high bit was 1, the shifted polynomial has degree 8.
    - Reduction by 0x11B is represented at byte level by XOR with 0x1B,
      because the x^8 term is discarded after masking to 8 bits.
    - This function is used by MixColumns and InvMixColumns for constants
      02, 03, 09, 0B, 0D, and 0E.
  */
  function gfMul(a, b) {
    let product = 0;
    let multiplicand = a & 0xff;
    let multiplier = b & 0xff;

    for (let i = 0; i < 8; i++) {
      if ((multiplier & 1) !== 0) product ^= multiplicand;
      const highBitSet = (multiplicand & 0x80) !== 0;
      multiplicand = (multiplicand << 1) & 0xff;
      if (highBitSet) multiplicand ^= 0x1b;
      multiplier >>= 1;
    }
    return product & 0xff;
  }

  function subBytes(state) {
    const out = cloneState(state);
    for (let r = 0; r < 4; r++) for (let c = 0; c < 4; c++) out[r][c] = SBOX[state[r][c]];
    return out;
  }

  function invSubBytes(state) {
    const out = cloneState(state);
    for (let r = 0; r < 4; r++) for (let c = 0; c < 4; c++) out[r][c] = INV_SBOX[state[r][c]];
    return out;
  }

  function shiftRows(state) {
    const out = cloneState(state);
    for (let r = 1; r < 4; r++) {
      for (let c = 0; c < 4; c++) out[r][c] = state[r][(c + r) % 4];
    }
    return out;
  }

  function invShiftRows(state) {
    const out = cloneState(state);
    for (let r = 1; r < 4; r++) {
      for (let c = 0; c < 4; c++) out[r][(c + r) % 4] = state[r][c];
    }
    return out;
  }

  function mixColumnsWithMatrix(state, matrix) {
    const out = cloneState(state);
    for (let c = 0; c < 4; c++) {
      const col = [state[0][c], state[1][c], state[2][c], state[3][c]];
      for (let r = 0; r < 4; r++) {
        out[r][c] = (
          gfMul(matrix[r][0], col[0]) ^
          gfMul(matrix[r][1], col[1]) ^
          gfMul(matrix[r][2], col[2]) ^
          gfMul(matrix[r][3], col[3])
        ) & 0xff;
      }
    }
    return out;
  }

  function mixColumns(state) {
    return mixColumnsWithMatrix(state, MIX_MATRIX);
  }

  function invMixColumns(state) {
    return mixColumnsWithMatrix(state, INV_MIX_MATRIX);
  }

  function addRoundKey(state, roundKeyBytes) {
    assertByteArray(roundKeyBytes, 16, "Round key");
    const out = cloneState(state);
    for (let c = 0; c < 4; c++) {
      for (let r = 0; r < 4; r++) out[r][c] = state[r][c] ^ roundKeyBytes[r + 4 * c];
    }
    return out;
  }

  function keyExpansion(keyBytes) {
    assertByteArray(keyBytes, 16, "Kunci AES-128");

    const words = [];
    const details = [];

    for (let i = 0; i < NK; i++) {
      words[i] = keyBytes.slice(4 * i, 4 * i + 4);
      details.push({
        i,
        type: "initial",
        baseWord: null,
        tempInput: null,
        rotWord: null,
        subWord: null,
        rcon: null,
        gOutput: null,
        formula: `W[${i}] = key[${4 * i}..${4 * i + 3}]`,
        result: words[i].slice()
      });
    }

    for (let i = NK; i < NB * (NR + 1); i++) {
      const tempInput = words[i - 1].slice();
      let transformed = tempInput.slice();
      let rotated = null;
      let substituted = null;
      let rcon = null;
      let type = "xor";

      if (i % NK === 0) {
        type = "g";
        rotated = rotWord(transformed);
        substituted = subWord(rotated);
        rcon = rconWord(i / NK);
        transformed = xorWords(substituted, rcon);
      }

      const result = xorWords(words[i - NK], transformed);
      words[i] = result;
      details.push({
        i,
        type,
        baseWord: words[i - NK].slice(),
        tempInput,
        rotWord: rotated,
        subWord: substituted,
        rcon,
        gOutput: transformed.slice(),
        formula: type === "g"
          ? `W[${i}] = W[${i - NK}] XOR (SubWord(RotWord(W[${i - 1}])) XOR Rcon[${i / NK}])`
          : `W[${i}] = W[${i - NK}] XOR W[${i - 1}]`,
        result: result.slice()
      });
    }

    const roundKeys = [];
    for (let round = 0; round <= NR; round++) {
      roundKeys.push(words.slice(round * NB, round * NB + NB).flat());
    }

    return { words, details, roundKeys };
  }

  function makeStep(name, before, after, options = {}) {
    return {
      name,
      before: before ? cloneState(before) : null,
      after: cloneState(after),
      key: options.key ? bytesToState(options.key) : null,
      kind: options.kind || "base",
      note: options.note || "",
      formula: options.formula || ""
    };
  }

  function encryptBlockTrace(inputBytes, keyBytes) {
    assertByteArray(inputBytes, 16, "Plaintext");
    assertByteArray(keyBytes, 16, "Kunci AES-128");

    const keySchedule = keyExpansion(keyBytes);
    const sections = [];
    let state = bytesToState(inputBytes);

    const initialPlain = cloneState(state);
    state = addRoundKey(state, keySchedule.roundKeys[0]);
    sections.push({
      id: "initial",
      title: "Initial Round",
      subtitle: "State awal plaintext dan AddRoundKey dengan RK0.",
      steps: [
        makeStep("State Awal Plaintext", null, initialPlain, { kind: "base", note: "Plaintext dipetakan ke State Matrix 4 x 4 secara column-major." }),
        makeStep("AddRoundKey RK0", initialPlain, state, { key: keySchedule.roundKeys[0], kind: "key", formula: "state = state XOR RK0" })
      ]
    });

    for (let round = 1; round <= 9; round++) {
      const steps = [];
      let before = cloneState(state);
      steps.push(makeStep(`Sebelum Round ${round}`, null, before, { kind: "base" }));

      state = subBytes(state);
      steps.push(makeStep("SubBytes", before, state, { kind: "subbytes", formula: "s[r,c] = SBOX[s[r,c]]" }));

      before = cloneState(state);
      state = shiftRows(state);
      steps.push(makeStep("ShiftRows", before, state, { kind: "shiftrows", formula: "row r digeser kiri sebanyak r byte" }));

      before = cloneState(state);
      state = mixColumns(state);
      steps.push(makeStep("MixColumns", before, state, { kind: "mixcolumns", formula: "setiap kolom dikali matriks [[02,03,01,01],...] dalam GF(2^8)" }));

      before = cloneState(state);
      state = addRoundKey(state, keySchedule.roundKeys[round]);
      steps.push(makeStep(`AddRoundKey RK${round}`, before, state, { key: keySchedule.roundKeys[round], kind: "key", formula: `state = state XOR RK${round}` }));

      sections.push({
        id: `round-${round}`,
        title: `Round ${round}`,
        subtitle: "SubBytes, ShiftRows, MixColumns, lalu AddRoundKey.",
        steps
      });
    }

    const finalSteps = [];
    let before = cloneState(state);
    finalSteps.push(makeStep("Sebelum Round 10", null, before, { kind: "base" }));

    state = subBytes(state);
    finalSteps.push(makeStep("SubBytes", before, state, { kind: "subbytes", formula: "s[r,c] = SBOX[s[r,c]]" }));

    before = cloneState(state);
    state = shiftRows(state);
    finalSteps.push(makeStep("ShiftRows", before, state, { kind: "shiftrows", formula: "row r digeser kiri sebanyak r byte" }));

    before = cloneState(state);
    state = addRoundKey(state, keySchedule.roundKeys[10]);
    finalSteps.push(makeStep("AddRoundKey RK10", before, state, { key: keySchedule.roundKeys[10], kind: "key", formula: "Final round tidak memakai MixColumns." }));

    sections.push({
      id: "round-10",
      title: "Round 10 Final",
      subtitle: "SubBytes, ShiftRows, dan AddRoundKey. Tidak ada MixColumns pada final round.",
      steps: finalSteps
    });

    const outputBytes = stateToBytes(state);
    return {
      mode: "encrypt",
      inputBytes: inputBytes.slice(),
      keyBytes: keyBytes.slice(),
      outputBytes,
      outputHex: bytesToHex(outputBytes),
      keySchedule,
      sections
    };
  }

  function decryptBlockTrace(inputBytes, keyBytes) {
    assertByteArray(inputBytes, 16, "Ciphertext");
    assertByteArray(keyBytes, 16, "Kunci AES-128");

    const keySchedule = keyExpansion(keyBytes);
    const sections = [];
    let state = bytesToState(inputBytes);

    const initialCipher = cloneState(state);
    state = addRoundKey(state, keySchedule.roundKeys[10]);
    sections.push({
      id: "dec-initial",
      title: "Dekripsi Initial",
      subtitle: "Ciphertext diawali dengan AddRoundKey menggunakan RK10.",
      steps: [
        makeStep("State Awal Ciphertext", null, initialCipher, { kind: "base", note: "Ciphertext dipetakan ke State Matrix 4 x 4 secara column-major." }),
        makeStep("AddRoundKey RK10", initialCipher, state, { key: keySchedule.roundKeys[10], kind: "key", formula: "state = state XOR RK10" })
      ]
    });

    for (let round = 9; round >= 1; round--) {
      const steps = [];
      let before = cloneState(state);
      steps.push(makeStep(`Sebelum Dekripsi Round ${round}`, null, before, { kind: "base" }));

      state = invShiftRows(state);
      steps.push(makeStep("InvShiftRows", before, state, { kind: "shiftrows", formula: "row r digeser kanan sebanyak r byte" }));

      before = cloneState(state);
      state = invSubBytes(state);
      steps.push(makeStep("InvSubBytes", before, state, { kind: "subbytes", formula: "s[r,c] = INV_SBOX[s[r,c]]" }));

      before = cloneState(state);
      state = addRoundKey(state, keySchedule.roundKeys[round]);
      steps.push(makeStep(`AddRoundKey RK${round}`, before, state, { key: keySchedule.roundKeys[round], kind: "key", formula: `state = state XOR RK${round}` }));

      before = cloneState(state);
      state = invMixColumns(state);
      steps.push(makeStep("InvMixColumns", before, state, { kind: "mixcolumns", formula: "setiap kolom dikali matriks inverse [[0e,0b,0d,09],...] dalam GF(2^8)" }));

      sections.push({
        id: `dec-round-${round}`,
        title: `Dekripsi Round ${round}`,
        subtitle: "InvShiftRows, InvSubBytes, AddRoundKey, lalu InvMixColumns.",
        steps
      });
    }

    const finalSteps = [];
    let before = cloneState(state);
    finalSteps.push(makeStep("Sebelum Final Round", null, before, { kind: "base" }));

    state = invShiftRows(state);
    finalSteps.push(makeStep("InvShiftRows", before, state, { kind: "shiftrows", formula: "row r digeser kanan sebanyak r byte" }));

    before = cloneState(state);
    state = invSubBytes(state);
    finalSteps.push(makeStep("InvSubBytes", before, state, { kind: "subbytes", formula: "s[r,c] = INV_SBOX[s[r,c]]" }));

    before = cloneState(state);
    state = addRoundKey(state, keySchedule.roundKeys[0]);
    finalSteps.push(makeStep("AddRoundKey RK0", before, state, { key: keySchedule.roundKeys[0], kind: "key", formula: "state = state XOR RK0" }));

    sections.push({
      id: "dec-final",
      title: "Dekripsi Final Round",
      subtitle: "InvShiftRows, InvSubBytes, dan AddRoundKey RK0. Tidak ada InvMixColumns pada final round.",
      steps: finalSteps
    });

    const outputBytes = stateToBytes(state);
    return {
      mode: "decrypt",
      inputBytes: inputBytes.slice(),
      keyBytes: keyBytes.slice(),
      outputBytes,
      outputHex: bytesToHex(outputBytes),
      outputText: blockToText(outputBytes),
      keySchedule,
      sections
    };
  }

  function encryptBlock(inputBytes, keyBytes) {
    return encryptBlockTrace(inputBytes, keyBytes).outputBytes;
  }

  function decryptBlock(inputBytes, keyBytes) {
    return decryptBlockTrace(inputBytes, keyBytes).outputBytes;
  }

  return {
    NB,
    NK,
    NR,
    SBOX,
    INV_SBOX,
    RCON,
    MIX_MATRIX,
    INV_MIX_MATRIX,
    hx,
    bytesToHex,
    wordToHex,
    cleanHex,
    hexToBytes,
    hexToBlock,
    textToBlock,
    blockToText,
    bytesToState,
    stateToBytes,
    cloneState,
    rotWord,
    subWord,
    rconWord,
    gfMul,
    subBytes,
    invSubBytes,
    shiftRows,
    invShiftRows,
    mixColumns,
    invMixColumns,
    addRoundKey,
    keyExpansion,
    encryptBlock,
    decryptBlock,
    encryptBlockTrace,
    decryptBlockTrace
  };
});
