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


const getByteParams = async function (setupFile, additionalPath) {
  const ppUrl = new URL(`${setupFile}.${additionalPath}`, "https://localhost:8090/build/").toString();
  const pp = await fetch(ppUrl).then((r) => r.arrayBuffer());
  console.log("byte_params", pp);
  return pp;
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
