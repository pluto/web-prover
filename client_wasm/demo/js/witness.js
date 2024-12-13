import { Buffer } from "buffer";
import { poseidon2 } from "poseidon-lite";
import { WitnessOutput } from "../pkg/client_wasm";
const _snarkjs = import("snarkjs");
const snarkjs = await _snarkjs;


export function compute_json_witness(padded_plaintext, key) {
  let plaintext = padded_plaintext.filter(isNullOrSpace);

  let plaintext_as_json = byteArrayToObject(plaintext);
  console.log()
  let data = JSON.stringify(plaintext_as_json[key]);
  let data_bytes = toByte(data);
  data_bytes = data_bytes.filter(isNullOrSpace);

  let startIdx = 0;
  let endIdx = 0;
  for (var i = 0; i < padded_plaintext.length; i++) {
    let filtered_body = padded_plaintext.slice(i, padded_plaintext.length).filter(isNullOrSpace);
    filtered_body = filtered_body.slice(0, data_bytes.length);
    if (arraysEqual(filtered_body, data_bytes) && filtered_body[0] === padded_plaintext[i]) {
      startIdx = i;
    }
  }

  for (var i = 0; i < padded_plaintext.length; i++) {
    let filtered_body = padded_plaintext.slice(0, i + 1).filter(isNullOrSpace);
    filtered_body.reverse();
    filtered_body = filtered_body.slice(0, data_bytes.length);
    filtered_body.reverse();
    if (arraysEqual(filtered_body, data_bytes) && filtered_body[data_bytes.length - 1] === padded_plaintext[i]) {
      endIdx = i;
    }
  }

  let result = [];
  for (var i = 0; i < padded_plaintext.length; i++) {
    if (i >= startIdx && i <= endIdx) {
      result.push(padded_plaintext[i]);
    } else {
      result.push(0);
    }
  }

  return result;
}

export function computeHttpWitnessStartline(paddedPlaintext, httpMaskType) {
  let result = Array(paddedPlaintext.length).fill(0);
  for (var i = 0; i < paddedPlaintext.length - 1; i++) {
    if (paddedPlaintext[i] === '\r'.charCodeAt(0) && paddedPlaintext[i + 1] === '\n'.charCodeAt(0)) {
      result.splice(0, i + 2, ...paddedPlaintext.slice(0, i + 2));
      break;
    }
  }

  return result;
}

export function computeHttpWitnessHeader(paddedPlaintext, headerName) {
  let result = Array(paddedPlaintext.length).fill(0);
  let currentHeader = 0;
  let currentHeaderName = [];
  let startPos = 0;

  // skip start line
  for (var i = 0; i < paddedPlaintext.length - 1; i++) {
    if (paddedPlaintext[i] === '\r'.charCodeAt(0) && paddedPlaintext[i + 1] === '\n'.charCodeAt(0)) {
      startPos = i + 2;
      break;
    }
  }

  let headerStartPos = startPos;
  for (var i = startPos; i < paddedPlaintext.length - 1; i++) {
    if (paddedPlaintext[i] == ':'.charCodeAt(0)) {
      currentHeaderName = paddedPlaintext.slice(headerStartPos, i);
    }

    if (paddedPlaintext[i] === '\r'.charCodeAt(0) && paddedPlaintext[i + 1] === '\n'.charCodeAt(0)) {
      if (arraysEqual(currentHeaderName, headerName)) {
        result.splice(headerStartPos, i + 2 - headerStartPos, ...paddedPlaintext.slice(headerStartPos, i + 2));
        break;
      }

      if (i + 3 < paddedPlaintext.length && paddedPlaintext[i + 2] === '\r'.charCodeAt(0) && paddedPlaintext[i + 3] === '\n'.charCodeAt(0)) {
        currentHeader = -1;
        break;
      }

      currentHeader = currentHeader + 1;
      headerStartPos = i + 2;
    }
  }

  return [currentHeader, result];
}

export function computeHttpWitnessBody(paddedPlaintext) {
  let result = Array(paddedPlaintext.length).fill(0);
  for (var i = 0; i < paddedPlaintext.length - 3; i++) {
    if (paddedPlaintext[i] === '\r'.charCodeAt(0) && paddedPlaintext[i + 1] === '\n'.charCodeAt(0) && paddedPlaintext[i + 2] === '\r'.charCodeAt(0) && paddedPlaintext[i + 3] === '\n'.charCodeAt(0)) {
      if (i + 4 < paddedPlaintext.length) {
        result.splice(i + 4, paddedPlaintext.length - i + 4, ...paddedPlaintext.slice(i + 4));
      }
      break;
    }
  }

  return result;
}

function DataHasher(input) {
  let hashes = [BigInt(0)];  // Initialize first hash as 0

  for (let i = 0; i < Math.ceil(input.length / 16); i++) {
    let packedInput = BigInt(0);
    let isPaddedChunk = 0;

    // Allow for using unpadded input:
    let innerLoopLength = 16;
    let lengthRemaining = input.length - 16 * i;
    if (lengthRemaining < 16) {
      innerLoopLength = lengthRemaining;
    }
    // Pack 16 bytes into a single number
    for (let j = 0; j < innerLoopLength; j++) {
      if (input[16 * i + j] != -1) {
        packedInput += BigInt(input[16 * i + j]) * BigInt(2 ** (8 * j));
      } else {
        isPaddedChunk += 1;
      }
    }

    // Compute next hash using previous hash and packed input, but if the whole block was padding, don't do it
    if (isPaddedChunk == innerLoopLength) {
      hashes.push(hashes[i]);
    } else {
      hashes.push(poseidon2([hashes[i], packedInput]));
    }
  }

  // Return the last hash
  return hashes[Math.ceil(input.length / 16)];
}

function toUint32Array(buf) {
  const arr = new Uint32Array(buf.length / 4)
  const arrView = new DataView(buf.buffer, buf.byteOffset, buf.byteLength)
  for (let i = 0; i < arr.length; i++) {
    arr[i] = arrView.getUint32(i * 4, true)
  }
  return arr
}

function uintArray32ToBits(uintArray) {
  const bits = []
  for (let i = 0; i < uintArray.length; i++) {
    const uint = uintArray[i]
    bits.push(numToBitsNumerical(uint))
  }

  return bits
}

export function numToBitsNumerical(num, bitCount = 32) {
  const bits = []
  for (let i = 2 ** (bitCount - 1); i >= 1; i /= 2) {
    const bit = num >= i ? 1 : 0
    bits.push(bit)
    num -= bit * i
  }

  return bits
}

function toInput(bytes) {
  return uintArray32ToBits(toUint32Array(bytes))
}

const getWitnessGenerator = async function (circuit) {
  const wasmUrl = new URL(`${circuit}.wasm`, `https://localhost:8090/build/target_512b/${circuit}_js/`).toString();
  const wasm = await fetch(wasmUrl).then((r) => r.arrayBuffer());
  return wasm;
}
async function generateWitness(input, wasm) {
  const witStart = +Date.now();
  let wtns = { type: "mem" };
  console.log("Calculating witness with wasm", wasm);
  console.log("input", input);
  await snarkjs.wtns.calculate(input, new Uint8Array(wasm), wtns);
  console.log("Witness calculated");
  const witEnd = +Date.now();
  console.log("witgen time:", witEnd - witStart);
  console.log("witness", wtns);
  return wtns;
}
const TOTAL_BYTES_ACROSS_NIVC = 512;

const make_nonce = function (iv, seq) {
  let nonce = new Uint8Array(12);
  nonce.fill(0);
  for (let i = 0; i < 8; i++) {
    nonce[4 + i] = seq >> (56 - 8 * i) & 0xff;
  }
  for (let i = 0; i < 12; i++) {
    nonce[i] ^= iv[i];
  }
  return nonce;
}

export const generateWitnessBytesForRequest = async function (circuits, inputs) {
  let witnesses = [];

  let plaintext = inputs.plaintext;
  let ciphertext = inputs.ciphertext;
  let extendedHTTPInput = plaintext.concat(Array(TOTAL_BYTES_ACROSS_NIVC - plaintext.length).fill(-1));
  let paddedCiphertext = ciphertext.concat(Array(TOTAL_BYTES_ACROSS_NIVC - ciphertext.length).fill(-1));

  console.log("CHACHA");
  let chachaInputs = {};
  chachaInputs["key"] = toInput(Buffer.from(inputs.key));
  chachaInputs["nonce"] = toInput(Buffer.from(make_nonce(inputs.iv, 0)));
  chachaInputs["plainText"] = extendedHTTPInput;
  chachaInputs["counter"] = uintArray32ToBits([1])[0];
  chachaInputs["step_in"] = DataHasher(paddedCiphertext);
  console.log("input generated 4", chachaInputs);

  // we get here in the dbg logs in the console. 
  let chachaWtns = await generateWitness(chachaInputs, await getWitnessGenerator(circuits[0]));
  witnesses.push(chachaWtns.data);

  // HTTP

  let httpInputs = {};
  httpInputs["start_line_hash"] = DataHasher(computeHttpWitnessStartline(extendedHTTPInput));
  httpInputs["header_hashes"] = Array(10).fill(0);
  for (var i = 0; i < inputs.headers.length; i++) {
    let computedHttpHeaderWitness = computeHttpWitnessHeader(extendedHTTPInput, toByte(inputs.headers[i]));
    let httpHeaderHash = DataHasher(computedHttpHeaderWitness[1]);
    httpInputs["header_hashes"][computedHttpHeaderWitness[0]] = httpHeaderHash;
  }
  let httpBody = computeHttpWitnessBody(extendedHTTPInput);
  httpInputs["body_hash"] = DataHasher(httpBody);
  httpInputs["step_in"] = DataHasher(extendedHTTPInput);
  httpInputs["data"] = extendedHTTPInput;

  let wtns = await generateWitness(circuits[1], httpInputs, await getWitnessGenerator(circuits[1]));
  witnesses.push(wtns.data);

  return witnesses;
};
export function toByte(data) {
  const byteArray = [];
  for (let i = 0; i < data.length; i++) {
    byteArray.push(data.charCodeAt(i));
  }
  return byteArray
}

export function isNullOrSpace(val) {
  return !(val == 0 || val == '\t'.charCodeAt(0) || val == '\n'.charCodeAt(0) || val == '\r'.charCodeAt(0) || val == '\x0C'.charCodeAt(0) || val == ' '.charCodeAt(0));
}

// Function to convert byte array to string
export function byteArrayToString(byteArray) {
  return Array.from(byteArray)
    .map(byte => String.fromCharCode(byte))
    .join('');
}

export function arraysEqual(a, b) {
  if (a === b) return true;
  if (a == null || b == null) return false;
  if (a.length !== b.length) return false;

  // If you don't care about the order of the elements inside
  // the array, you should sort both arrays here.
  // Please note that calling sort on an array will modify that array.
  // you might want to clone your array first.

  for (var i = 0; i < a.length; ++i) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// Function to convert byte array to object with multiple parsing methods
export function byteArrayToObject(byteArray) {
  try {
    // Method 1: Using TextDecoder
    if (typeof TextDecoder !== 'undefined') {
      const decoder = new TextDecoder('utf-8');
      const jsonString = decoder.decode(new Uint8Array(byteArray));
      return JSON.parse(jsonString);
    }

    // Method 2: Manual conversion (fallback)
    const jsonString = byteArrayToString(byteArray);
    return JSON.parse(jsonString);
  } catch (error) {
    throw new Error(`Failed to convert byte array to object: ${error.message}`);
  }
}

// this is exposed via FFI to the rust code
/// it will be called there after as part of the executions trace of the prove function
export const witness = {
  createWitness: async (input) => {
    console.log("createWitness", input);
    // circuits need to be 512b
    var circuits = ["plaintext_authentication_512b", "http_verification_512b", "json_mask_object_512b", "json_mask_array_index_512b", "json_extract_value_512b"];
    // var witnesses = await generateWitnessBytesForRequest(circuits, input);
    let witnesses = new WitnessOutput([new Uint8Array(0), new Uint8Array(0)]);
    console.log("witness", witnesses);
    return witnesses;
  }
};


if (typeof window !== 'undefined') {
  window.witness = witness;  // For main thread
} else if (typeof self !== 'undefined') {
  self.witness = witness;    // For worker thread
}