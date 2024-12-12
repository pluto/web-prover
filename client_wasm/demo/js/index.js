import init, {
  setup_tracing,
  initThreadPool,
} from "../pkg/client_wasm.js";
import { poseidon2 } from "poseidon-lite";
import { toByte, computeHttpWitnessBody, computeHttpWitnessHeader, computeHttpWitnessStartline, compute_json_witness, byteArrayToString } from "./witness.js";
import { Buffer } from "buffer";
import { witness } from "./witness";


const _snarkjs = import("snarkjs");
const snarkjs = await _snarkjs;

const numConcurrency = navigator.hardwareConcurrency;

// Create a WebAssembly.Memory object
const memory = new WebAssembly.Memory({
  initial: 16384, // 256 pages = 16MB
  maximum: 65536, // 1024 pages = 64MB
  shared: true, // Enable shared memory
});

const TOTAL_BYTES_ACROSS_NIVC = 1024;
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


const getWitnessGenerator = async function (circuit) {
  const wasmUrl = new URL(`${circuit}.wasm`, `https://localhost:8090/build/target_512b/${circuit}_js/`).toString();
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

export const generateWitnessBytesForRequest = async function (circuits, inputs) {
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
  inputs[1]["header_hashes"] = Array(10).fill(0);
  inputs[1]["header_hashes"][0] = http_header_0_hash;
  inputs[1]["header_hashes"][1] = http_header_1_hash;
  inputs[1]["body_hash"] = DataHasher(http_body);
  inputs[1]["step_in"] = DataHasher(extendedHTTPInput);
  inputs[1]["data"] = extendedHTTPInput;

  let wtns = await generateWitness(circuits[1], inputs[1], await getWitnessGenerator(circuits[1]));
  witnesses.push(wtns.data);

  return witnesses;
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
var proving_params = {
  aux_params: await getByteParams("serialized_setup_aes", "bytes"),
};
proofWorker.postMessage({ proverConfig, proving_params, memory });
console.log("message sent to worker");
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
