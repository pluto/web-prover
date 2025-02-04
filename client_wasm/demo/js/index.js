import init, { setup_tracing, initThreadPool } from "../pkg/client_wasm.js";
import { witness } from "./witness"; // This is not unused, this is how we initialize window.witness
import { WEB_PROVER_CIRCUITS_VERSION } from "./config";
import teeConfig from "../../../fixture/client.tee_tcp_local.json";
import origoConfig from "../../../fixture/client.origo_tcp_local.json";
import tlsnConfig from "../../../fixture/client.tlsn_tcp_local.json";
import { DEFAULT_MODE } from "../scripts/test.js";

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
const sharedMemory = new WebAssembly.Memory({
  initial: 16384, // 16,384 pages = 1GB
  maximum: 49152, // 49,152 pages = 3GB
  shared: true, // Enable shared memory
});

await init(undefined, sharedMemory);
setup_tracing("debug,tlsn_extension_rs=debug");
await initThreadPool(numConcurrency);
console.log("initialized thread pool", numConcurrency);
console.log(`Thread pool initialized with ${numConcurrency} threads`);
if (navigator.hardwareConcurrency) {
  console.log(`Hardware concurrency: ${navigator.hardwareConcurrency}`);
}
startMemoryMonitoring(sharedMemory);

let startTime, endTime, startPreWitgenTime;

function start() {
  startTime = performance.now();
}

function end() {
  endTime = performance.now();
  let timeDiff = endTime - startTime;
  timeDiff /= 1000;

  let timeDiffWitgen = endTime - startPreWitgenTime;
  timeDiffWitgen /= 1000;

  console.log(Math.round(timeDiff) + " seconds");
  console.log(Math.round(timeDiffWitgen) + " seconds (including witness)");
}

const getBytes = async function (file) {
  const ppUrl = new URL(
    `build/${file}`,
    window.location.origin,
  ).toString();
  const buffer = await fetch(ppUrl).then((r) => r.arrayBuffer());
  console.log("buffer.byteLength", buffer.byteLength);
  if (buffer.byteLength === 0) {
    throw new Error(`Failed to load ${file}`);
  }
  return new Uint8Array(buffer); // Cast to a js-sys (WASM) friendly type
};

start();

const mode = window.MODE || DEFAULT_MODE; // Get the mode from window object
const proverConfig = {};
if (mode === "tee") {
  proverConfig.config = teeConfig;
} else if (mode === "origo") {
  proverConfig.config = origoConfig;
} else if (mode === "tlsn") {
  proverConfig.config = tlsnConfig;
} else {
  throw new Error(`Invalid mode: ${mode}`);
}

console.log(`Using ${mode} mode`);

const proofWorker = new Worker(new URL("./proof.js", import.meta.url), {
  type: "module",
});
console.log("sending message to worker");
console.log(WEB_PROVER_CIRCUITS_VERSION)

function artifactPath(name) {
  return `circom-artifacts-512b-v${WEB_PROVER_CIRCUITS_VERSION}/${name}`;
}

const provingParams = {
  aux_params: await getBytes(artifactPath('serialized_setup_512b_rom_length_100.bin')),
};
const r1csTypes = [
  await getBytes(artifactPath('plaintext_authentication_512b.r1cs')),
  await getBytes(artifactPath('http_verification_512b.r1cs')),
  await getBytes(artifactPath('json_extraction_512b.r1cs')),
];

proofWorker.postMessage({
  proverConfig,
  provingParams,
  r1csTypes,
  sharedMemory,
});
console.log("message sent to worker");
proofWorker.onmessage = (event) => {
  if (event.data.error) {
    console.error("Error from worker:", event.data.error);
  } else if (event.data.type === "log") {
    console.log(...event.data.data);
  } else {
    if ("type" in event.data && event.data.type === "proof") {
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
