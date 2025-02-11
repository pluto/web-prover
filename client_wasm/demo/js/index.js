import init, { setup_tracing, initThreadPool } from "../pkg/client_wasm.js";
import { witness } from "./witness";
import { WEB_PROVER_CIRCUITS_VERSION } from "./config";

const numConcurrency = navigator.hardwareConcurrency;

// Monitoring for WASM memory usage
function checkWasmMemory(wasmMemory) {
  const memoryMB = wasmMemory.buffer.byteLength / (1024 * 1024);
  console.log(
    `${new Date().toISOString()}: WASM Memory Usage: ${memoryMB.toFixed(2)} MB`,
  );
}

function startMemoryMonitoring(instance) {
  checkWasmMemory(instance);
  setInterval(() => {
    checkWasmMemory(instance);
  }, 5000);
}
// Create a WebAssembly.Memory object
const shared_memory = new WebAssembly.Memory({
  initial: 16384, // 256 pages = 16MB
  maximum: 36000, // 1024 pages = 64MB
  shared: true, // Enable shared memory
});

await init(undefined, shared_memory);
setup_tracing("debug,tlsn_extension_rs=debug");
await initThreadPool(numConcurrency);
console.log("initialized thread pool", numConcurrency);
console.log(`Thread pool initialized with ${numConcurrency} threads`);
if (navigator.hardwareConcurrency) {
  console.log(`Hardware concurrency: ${navigator.hardwareConcurrency}`);
}
startMemoryMonitoring(shared_memory);

var startTime, endTime, startPreWitgenTime;

function start() {
  startTime = performance.now();
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

const getByteParams = async function (setupFile) {
  const ppUrl = new URL(
    `build/${setupFile}`,
    window.location.origin,
  ).toString();
  const pp = await fetch(ppUrl).then((r) => r.arrayBuffer());
  console.log("byte_params", pp);
  return pp;
};

start();

import proverConfig from "../../../fixture/client.origo_tcp_local.json";

const proofWorker = new Worker(new URL("./proof.js", import.meta.url), {
  type: "module",
});
console.log("sending message to worker");
console.log(WEB_PROVER_CIRCUITS_VERSION)

var proving_params = {
  aux_params: await getByteParams(
    `circom-artifacts-512b-v${WEB_PROVER_CIRCUITS_VERSION}/serialized_setup_512b_rom_length_100.bin`,
  ),
};
proofWorker.postMessage({
  proverConfig,
  proving_params,
  shared_memory,
});
console.log("message sent to worker");
proofWorker.onmessage = (event) => {
  if (event.data.error) {
    console.error("Error from worker:", event.data.error);
  } else if (event.data.type === "log") {
    console.log(...event.data.data);
  } else {
    if ("type" in event.data && event.data.type == "proof") {
      console.log("proof successfully generated: ", event.data);
    } else {
      console.error("Error from worker:", event.data)
    }
  }
};

end();

// ./fixture/cets/notary.pub
const pubkey =
  "-----BEGIN PUBLIC KEY-----\n" +
  "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEBv36FI4ZFszJa0DQFJ3wWCXvVLFr\n" +
  "cRzMG5kaTeHGoSzDu6cFqx3uEWYpFGo6C0EOUgf+mEgbktLrXocv5yHzKg==\n" +
  "-----END PUBLIC KEY-----\n";

// const verifyResult = JSON.parse(await verify(proof, pubkey));

// console.log(verifyResult);
