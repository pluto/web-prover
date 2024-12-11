import init, {
  setup_tracing,
  initThreadPool
} from "../pkg/client_wasm.js";
import { poseidon2 } from "poseidon-lite";
import { toByte, computeHttpWitnessBody, computeHttpWitnessHeader, computeHttpWitnessStartline, compute_json_witness, byteArrayToString } from "./witness.js";
import { Buffer } from "buffer";
const numConcurrency = navigator.hardwareConcurrency;

// Create a WebAssembly.Memory object
const memory = new WebAssembly.Memory({
  initial: 16384, // 256 pages = 16MB
  maximum: 65536, // 1024 pages = 64MB
  shared: true, // Enable shared memory
});

await init(undefined, memory);
setup_tracing("debug,tlsn_extension_rs=debug");
await initThreadPool(numConcurrency);

var startTime, endTime, startPreWitgenTime;

function start() {
  startTime = performance.now();
}
function startPreWitgen() {
  startPreWitgenTime = performance.now();
}

function end() {
  endTime = performance.now();
  var timeDiff = endTime - startTime;
  timeDiff /= 1000;

  var timeDiffWitgen = endTime - startPreWitgenTime;
  timeDiffWitgen /= 1000;

  console.log(Math.round(timeDiff) + " seconds");
  console.log(Math.round(timeDiffWitgen) + " seconds (including witness)");
}

const _snarkjs = import("snarkjs");
const snarkjs = await _snarkjs;

const getWitnessGenerator = async function (circuit) {
  const wasmUrl = new URL(`${circuit}.wasm`, `https://localhost:8090/build/target_1024b/${circuit}_js/`).toString();
  const wasm = await fetch(wasmUrl).then((r) => r.arrayBuffer());
  return wasm;
}

const getByteParams = async function (setupFile, additionalPath) {
  const ppUrl = new URL(`${setupFile}.${additionalPath}`, "https://localhost:8090/build/").toString();
  const pp = await fetch(ppUrl).then((r) => r.arrayBuffer());
  console.log("byte_params", pp);
  return pp;
}

async function generateWitness(circuit, input, wasm) {
  const witStart = +Date.now();
  let wtns = { type: "mem" };
  await snarkjs.wtns.calculate(input, new Uint8Array(wasm), wtns);
  const witEnd = +Date.now();
  console.log("witgen time:", witEnd - witStart);
  console.log("witness", wtns);
  return wtns;
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

const generateWitnessBytesForResponse = async function (circuits, inputs) {
  let witnesses = [];

  let plaintext = inputs[0]["plainText"];
  let extendedHTTPInput = plaintext.concat(Array(TOTAL_BYTES_ACROSS_NIVC - plaintext.length).fill(0));

  // AES
  console.log("AES");
  let plaintext_length = plaintext.length;
  let cipherText = inputs[0]["cipherText"].concat(Array(TOTAL_BYTES_ACROSS_NIVC - plaintext.length).fill(0));
  let cached_wasm = {};

  inputs[0]["step_in"] = 0;
  for (var i = 0; i < plaintext_length / 16; i++) {
    inputs[0]["plainText"] = plaintext.slice(i * 16, (i + 1) * 16);
    inputs[0]["cipherText"] = cipherText.slice(i * 16, (i + 1) * 16);
    inputs[0]["ctr"] = [0, 0, 0, i + 1];
    console.log("inputs[0]", inputs[0]);
    if (!(circuits[0] in cached_wasm)) {
      const wasm = await getWitnessGenerator(circuits[0]);
      cached_wasm[circuits[0]] = wasm;
    }
    let wtns = await generateWitness(circuits[0], inputs[0], cached_wasm[circuits[0]]);
    witnesses.push(wtns.data);
    inputs[0]["step_in"] = DataHasher(plaintext.slice(0, (i + 1) * 16));
  };

  // HTTP
  let http_start_line = computeHttpWitnessStartline(extendedHTTPInput);
  let http_header_0 = computeHttpWitnessHeader(extendedHTTPInput, toByte("content-type"));
  let http_header_1 = computeHttpWitnessHeader(extendedHTTPInput, toByte("content-encoding"));
  let http_body = computeHttpWitnessBody(extendedHTTPInput);

  inputs[1]["start_line_hash"] = DataHasher(http_start_line);
  let http_header_0_hash = DataHasher(http_header_0[1]);
  let http_header_1_hash = DataHasher(http_header_1[1]);
  inputs[1]["header_hashes"] = [http_header_0_hash, http_header_1_hash, 0, 0, 0, 0, 0, 0, 0, 0];
  inputs[1]["body_hash"] = DataHasher(http_body);
  inputs[1]["step_in"] = DataHasher(extendedHTTPInput);
  inputs[1]["data"] = extendedHTTPInput;
  let wtns = await generateWitness(circuits[1], inputs[1], await getWitnessGenerator(circuits[1]));
  witnesses.push(wtns.data);

  console.log("json mask object");
  inputs[2]["data"] = http_body;
  inputs[2]["step_in"] = DataHasher(http_body);
  let json_wasm = await getWitnessGenerator(circuits[2])
  let wtnsJsonKey1 = await generateWitness(circuits[2], inputs[2], json_wasm);
  witnesses.push(wtnsJsonKey1.data);

  console.log("json mask object");
  let jsonWitnessKey1 = compute_json_witness(http_body, byteArrayToString(inputs[2]["key"].slice(0, inputs[2]["keyLen"])));
  inputs[3]["data"] = jsonWitnessKey1;
  inputs[3]["step_in"] = DataHasher(jsonWitnessKey1);
  let wtnsJsonKey2 = await generateWitness(circuits[2], inputs[3], json_wasm);
  witnesses.push(wtnsJsonKey2.data);

  console.log("json mask array");
  let jsonWitnessKey2 = compute_json_witness(jsonWitnessKey1, byteArrayToString(inputs[3]["key"].slice(0, inputs[3]["keyLen"])));
  inputs[4]["data"] = jsonWitnessKey2;
  inputs[4]["step_in"] = DataHasher(jsonWitnessKey2);
  let wtnsJsonKey3 = await generateWitness(circuits[3], inputs[4], await getWitnessGenerator(circuits[3]));
  witnesses.push(wtnsJsonKey3.data);

  console.log("json mask object");
  let jsonWitnessKey3 = compute_json_witness(jsonWitnessKey2, inputs[4]["index"]);
  inputs[5]["data"] = jsonWitnessKey3;
  inputs[5]["step_in"] = DataHasher(jsonWitnessKey3);
  let wtnsJsonKey4 = await generateWitness(circuits[2], inputs[5], json_wasm);
  witnesses.push(wtnsJsonKey4.data);

  console.log("json mask object");
  let jsonWitnessKey4 = compute_json_witness(jsonWitnessKey3, byteArrayToString(inputs[5]["key"].slice(0, inputs[5]["keyLen"])));
  inputs[6]["data"] = jsonWitnessKey4;
  inputs[6]["step_in"] = DataHasher(jsonWitnessKey4);
  let wtnsJsonKey5 = await generateWitness(circuits[2], inputs[6], json_wasm);
  witnesses.push(wtnsJsonKey5.data);

  console.log("json extract value");
  let jsonWitnessKey5 = compute_json_witness(jsonWitnessKey4, byteArrayToString(inputs[6]["key"].slice(0, inputs[6]["keyLen"])));
  inputs[7]["data"] = jsonWitnessKey5
  inputs[7]["step_in"] = DataHasher(jsonWitnessKey5);
  let wtnsFinal = await generateWitness(circuits[4], inputs[7], await getWitnessGenerator(circuits[4]));
  console.log("wtnsFinal", wtnsFinal);
  witnesses.push(wtnsFinal.data);

  return witnesses;
};

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

const generateWitnessBytesForRequest = async function (circuits, inputs) {
  let witnesses = [];

  let plaintext = inputs[0]["plainText"];
  let extendedHTTPInput = plaintext.concat(Array(TOTAL_BYTES_ACROSS_NIVC - plaintext.length).fill(-1));
  let paddedCiphertext = CHACHA20_CIPHERTEXT.concat(Array(TOTAL_BYTES_ACROSS_NIVC - CHACHA20_CIPHERTEXT.length).fill(-1));

  console.log("CHACHA");
  inputs[0]["key"] = toInput(Buffer.from(inputs[0]["key"]));
  inputs[0]["nonce"] = toInput(Buffer.from(inputs[0]["nonce"]));
  inputs[0]["plainText"] = extendedHTTPInput;
  inputs[0]["counter"] = uintArray32ToBits([1])[0];
  inputs[0]["step_in"] = DataHasher(paddedCiphertext);

  let chachaWtns = await generateWitness(circuits[0], inputs[0], await getWitnessGenerator(circuits[0]));
  witnesses.push(chachaWtns.data);

  // HTTP
  let http_start_line = computeHttpWitnessStartline(extendedHTTPInput);
  let http_header_0 = computeHttpWitnessHeader(extendedHTTPInput, toByte("content-type"));
  let http_header_1 = computeHttpWitnessHeader(extendedHTTPInput, toByte("content-encoding"));
  let http_body = computeHttpWitnessBody(extendedHTTPInput);

  inputs[1]["start_line_hash"] = DataHasher(http_start_line);
  let http_header_0_hash = DataHasher(http_header_0[1]);
  let http_header_1_hash = DataHasher(http_header_1[1]);
  inputs[1]["header_hashes"] = Array(25).fill(0);
  inputs[1]["header_hashes"][0] = http_header_0_hash;
  inputs[1]["header_hashes"][1] = http_header_1_hash;
  inputs[1]["body_hash"] = DataHasher(http_body);
  inputs[1]["step_in"] = DataHasher(extendedHTTPInput);
  inputs[1]["data"] = extendedHTTPInput;

  let wtns = await generateWitness(circuits[1], inputs[1], await getWitnessGenerator(circuits[1]));
  witnesses.push(wtns.data);

  // console.log("json mask object");
  // inputs[2]["data"] = http_body;
  // inputs[2]["step_in"] = DataHasher(http_body);
  // let wtnsJsonKey1 = await generateWitness(circuits[2], inputs[2]);
  // witnesses.push({
  //   val: wtnsJsonKey1.data,
  // });

  // console.log("json mask object");
  // let jsonWitnessKey1 = compute_json_witness(http_body, byteArrayToString(inputs[2]["key"].slice(0, inputs[2]["keyLen"])));
  // inputs[3]["data"] = jsonWitnessKey1;
  // inputs[3]["step_in"] = DataHasher(jsonWitnessKey1);
  // let wtnsJsonKey2 = await generateWitness(circuits[2], inputs[3]);
  // witnesses.push({
  //   val: wtnsJsonKey2.data,
  // });

  // console.log("json mask array");
  // let jsonWitnessKey2 = compute_json_witness(jsonWitnessKey1, byteArrayToString(inputs[3]["key"].slice(0, inputs[3]["keyLen"])));
  // inputs[4]["data"] = jsonWitnessKey2;
  // inputs[4]["step_in"] = DataHasher(jsonWitnessKey2);
  // let wtnsJsonKey3 = await generateWitness(circuits[3], inputs[4]);
  // witnesses.push({
  //   val: wtnsJsonKey3.data,
  // });

  // console.log("json mask object");
  // let jsonWitnessKey3 = compute_json_witness(jsonWitnessKey2, inputs[4]["index"]);
  // inputs[5]["data"] = jsonWitnessKey3;
  // inputs[5]["step_in"] = DataHasher(jsonWitnessKey3);
  // let wtnsJsonKey4 = await generateWitness(circuits[2], inputs[5]);
  // witnesses.push({
  //   val: wtnsJsonKey4.data,
  // });

  // console.log("json mask object");
  // let jsonWitnessKey4 = compute_json_witness(jsonWitnessKey3, byteArrayToString(inputs[5]["key"].slice(0, inputs[5]["keyLen"])));
  // inputs[6]["data"] = jsonWitnessKey4;
  // inputs[6]["step_in"] = DataHasher(jsonWitnessKey4);
  // let wtnsJsonKey5 = await generateWitness(circuits[2], inputs[6]);
  // witnesses.push({
  //   val: wtnsJsonKey5.data,
  // });

  // console.log("json extract value");
  // let jsonWitnessKey5 = compute_json_witness(jsonWitnessKey4, byteArrayToString(inputs[6]["key"].slice(0, inputs[6]["keyLen"])));
  // inputs[7]["data"] = jsonWitnessKey5
  // inputs[7]["step_in"] = DataHasher(jsonWitnessKey5);
  // let wtnsFinal = await generateWitness(circuits[4], inputs[7]);
  // console.log("wtnsFinal", wtnsFinal);
  // witnesses.push({
  //   val: wtnsFinal.data,
  // });

  return witnesses;
};

const TOTAL_BYTES_ACROSS_NIVC = 1024;

// 256 bytes
const PLAINTEXT = [
  72, 84, 84, 80, 47, 49, 46, 49, 32, 50, 48, 48, 32, 79, 75, 13, 10, 99, 111, 110, 116, 101, 110,
  116, 45, 116, 121, 112, 101, 58, 32, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 47, 106,
  115, 111, 110, 59, 32, 99, 104, 97, 114, 115, 101, 116, 61, 117, 116, 102, 45, 56, 13, 10, 99,
  111, 110, 116, 101, 110, 116, 45, 101, 110, 99, 111, 100, 105, 110, 103, 58, 32, 103, 122, 105,
  112, 13, 10, 84, 114, 97, 110, 115, 102, 101, 114, 45, 69, 110, 99, 111, 100, 105, 110, 103, 58,
  32, 99, 104, 117, 110, 107, 101, 100, 13, 10, 13, 10, 123, 13, 10, 32, 32, 32, 34, 100, 97, 116,
  97, 34, 58, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 34, 105, 116, 101, 109, 115, 34, 58, 32,
  91, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32,
  32, 32, 32, 32, 32, 32, 32, 32, 34, 100, 97, 116, 97, 34, 58, 32, 34, 65, 114, 116, 105, 115,
  116, 34, 44, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 34, 112, 114,
  111, 102, 105, 108, 101, 34, 58, 32, 123, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
  32, 32, 32, 32, 34, 110, 97, 109, 101, 34, 58, 32, 34, 84, 97, 121, 108, 111, 114, 32, 83, 119,
  105, 102, 116, 34, 13, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 13,
  10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 13, 10, 32, 32, 32, 32, 32, 32, 32, 93, 13,
  10, 32, 32, 32, 125, 13, 10, 125,
];

const CHACHA20_CIPHERTEXT = [
  2, 125, 219, 141, 140, 93, 49, 129, 95, 178, 135, 109, 48, 36, 194, 46, 239, 155, 160, 70, 208,
  147, 37, 212, 17, 195, 149, 190, 38, 215, 23, 241, 84, 204, 167, 184, 179, 172, 187, 145, 38, 75,
  123, 96, 81, 6, 149, 36, 135, 227, 226, 254, 177, 90, 241, 159, 0, 230, 183, 163, 210, 88, 133,
  176, 9, 122, 225, 83, 171, 157, 185, 85, 122, 4, 110, 52, 2, 90, 36, 189, 145, 63, 122, 75, 94,
  21, 163, 24, 77, 85, 110, 90, 228, 157, 103, 41, 59, 128, 233, 149, 57, 175, 121, 163, 185, 144,
  162, 100, 17, 34, 9, 252, 162, 223, 59, 221, 106, 127, 104, 11, 121, 129, 154, 49, 66, 220, 65,
  130, 171, 165, 43, 8, 21, 248, 12, 214, 33, 6, 109, 3, 144, 52, 124, 225, 206, 223, 213, 86, 186,
  93, 170, 146, 141, 145, 140, 57, 152, 226, 218, 57, 30, 4, 131, 161, 0, 248, 172, 49, 206, 181,
  47, 231, 87, 72, 96, 139, 145, 117, 45, 77, 134, 249, 71, 87, 178, 239, 30, 244, 156, 70, 118,
  180, 176, 90, 92, 80, 221, 177, 86, 120, 222, 223, 244, 109, 150, 226, 142, 97, 171, 210, 38,
  117, 143, 163, 204, 25, 223, 238, 209, 58, 59, 100, 1, 86, 241, 103, 152, 228, 37, 187, 79, 36,
  136, 133, 171, 41, 184, 145, 146, 45, 192, 173, 219, 146, 133, 12, 246, 190, 5, 54, 99, 155, 8,
  198, 156, 174, 99, 12, 210, 95, 5, 128, 166, 118, 50, 66, 26, 20, 3, 129, 232, 1, 192, 104, 23,
  152, 212, 94, 97, 138, 162, 90, 185, 108, 221, 211, 247, 184, 253, 15, 16, 24, 32, 240, 240, 3,
  148, 89, 30, 54, 161, 131, 230, 161, 217, 29, 229, 251, 33, 220, 230, 102, 131, 245, 27, 141,
  220, 67, 16, 26,
];
const CHACHA20_KEY = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const CHACHA20_NONCE = [0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0];


var inputs = [
  {
    "key": CHACHA20_KEY,
    "nonce": CHACHA20_NONCE,
    "plainText": PLAINTEXT,
    "counter": [1],
  },
  {
    "data": PLAINTEXT,
  },
  // { "key": [100, 97, 116, 97, 0, 0, 0, 0, 0, 0], "keyLen": [4] },
  // { "key": [105, 116, 101, 109, 115, 0, 0, 0, 0, 0], "keyLen": [5] },
  // { "index": [0] },
  // { "key": [112, 114, 111, 102, 105, 108, 101, 0, 0, 0], "keyLen": [7] },
  // { "key": [110, 97, 109, 101, 0, 0, 0, 0, 0, 0], "keyLen": [4] },
  // {},
];


startPreWitgen();

// TODO: Configurable identifiers
var circuits = ["plaintext_authentication_1024b", "http_verification_1024b", "json_mask_object_1024b", "json_mask_array_index_1024b", "json_extract_value_1024b"];
var witnesses = await generateWitnessBytesForRequest(circuits, inputs);
console.log("witness", witnesses);

var proving_params = {
  aux_params: await getByteParams("serialized_setup_aes", "bytes"),
  witnesses: witnesses,
};

start();

let proverConfig = {
  mode: "Origo",
  notary_host: "localhost",
  notary_port: 7443,
  target_method: "GET",
  target_url: "https://gist.githubusercontent.com/mattes/23e64faadb5fd4b5112f379903d2572e/raw/74e517a60c21a5c11d94fec8b572f68addfade39/example.json",
  target_headers: {},
  target_body: "",
  max_sent_data: 10000,
  max_recv_data: 10000,
  proving: {
    witnesses: [],
    manifest: {
      "manifestVersion": "1",
      "id": "reddit-user-karma",
      "title": "Total Reddit Karma",
      "description": "Generate a proof that you have a certain amount of karma",
      "prepareUrl": "https://www.reddit.com/login/",
      "request": {
        "method": "GET",
        "version": "HTTP/1.1",
        "url": "https://gist.githubusercontent.com/mattes/23e64faadb5fd4b5112f379903d2572e/raw/74e517a60c21a5c11d94fec8b572f68addfade39/example.json",
        "headers": {
          "accept-encoding": "identity"
        },
        "body": {
          "userId": "<% userId %>"
        },
        "vars": {
          "userId": {
            "regex": "[a-z]{,20}+"
          },
          "token": {
            "type": "base64",
            "length": 32
          }
        }
      },
      "response": {
        "status": "200",
        "version": "HTTP/1.1",
        "message": "OK",
        "headers": {
          "Content-Type": "application/json"
        },
        "body": {
          "json": [
            "data",
            "items",
            0
          ],
          "contains": "this_string_exists_in_body"
        }
      }
    },
  }
};

const proofWorker = new Worker(new URL("./proof.js", import.meta.url), { type: "module" });
console.log("sending message to worker");
proofWorker.postMessage({ proverConfig, proving_params, memory });

proofWorker.onmessage = (event) => {
  if (event.data.error) {
    console.error("Error from worker:", event.data.error);
  } else {
    console.log("proof generated!", event.data);
  }
}
// TODO: Call this in a web worker so the main thread doesn't hang.
// Config for local development
// const proof = await prover({
//   mode: "Origo",
//   notary_host: "localhost",
//   notary_port: 7443,
//   target_method: "GET",
//   target_url: "https://gist.githubusercontent.com/mattes/23e64faadb5fd4b5112f379903d2572e/raw/74e517a60c21a5c11d94fec8b572f68addfade39/example.json",
//   target_headers: {},
//   target_body: "",
//   max_sent_data: 10000,
//   max_recv_data: 10000,
//   proving: {
//     r1cs: r1cs,
//     witnesses: witnesses,
//     params: pp,
//   }
// });

// const proof = await prover({
//   mode: "TLSN",
//   notary_host: "localhost",
//   notary_port: 7443,
//   target_method: "GET",
//   target_url:
//     "https://gist.githubusercontent.com/mattes/23e64faadb5fd4b5112f379903d2572e/raw/74e517a60c21a5c11d94fec8b572f68addfade39/example.json", // "https://localhost:8085/health",
//   target_headers: {},
//   target_body: "",
//   websocket_proxy_url: "wss://localhost:7443/v1/tlsnotary/websocket_proxy",
//   max_sent_data: 10000,
//   max_recv_data: 10000,
// });

// Config using notary.pluto.dev
// const proof = await prover({
//   mode: "TLSN",
//   notary_host: "notary.pluto.dev",
//   notary_port: 443,
//   target_method: "GET",
//   target_url: "https://gist.githubusercontent.com/mattes/23e64faadb5fd4b5112f379903d2572e/raw/74e517a60c21a5c11d94fec8b572f68addfade39/example.json",
//   target_headers: {},
//   target_body: "",
//   websocket_proxy_url: "wss://notary.pluto.dev/v1/tlsnotary/websocket_proxy",
//   max_sent_data: 10000,
//   max_recv_data: 10000,
// });

// console.log(proof);
end();

// ./fixture/cets/notary.pub
const pubkey =
  "-----BEGIN PUBLIC KEY-----\n" +
  "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEBv36FI4ZFszJa0DQFJ3wWCXvVLFr\n" +
  "cRzMG5kaTeHGoSzDu6cFqx3uEWYpFGo6C0EOUgf+mEgbktLrXocv5yHzKg==\n" +
  "-----END PUBLIC KEY-----\n";

// const verifyResult = JSON.parse(await verify(proof, pubkey));

// console.log(verifyResult);
