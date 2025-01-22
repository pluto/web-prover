import init, {
  setup_tracing,
  initThreadPool,
} from "../pkg/client_wasm.js";
import { witness } from "./witness";

const numConcurrency = navigator.hardwareConcurrency;

// Create a WebAssembly.Memory object
const shared_memory = new WebAssembly.Memory({
  initial: 16384, // 256 pages = 16MB
  maximum: 65536, // 1024 pages = 64MB
  shared: true, // Enable shared memory
});

await init(undefined, shared_memory);
setup_tracing("debug,tlsn_extension_rs=debug");
await initThreadPool(numConcurrency);

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
  const ppUrl = new URL(`${setupFile}`, "https://localhost:8090/build/").toString();
  const pp = await fetch(ppUrl).then((r) => r.arrayBuffer());
  console.log("byte_params", pp);
  return pp;
}

start();

import proverConfig from "../../../fixture/client.origo_tcp_local.json";

const proofWorker = new Worker(new URL("./proof.js", import.meta.url), { type: "module" });
console.log("sending message to worker");
var proving_params = {
  aux_params: await getByteParams("circom-artifacts-1024b-v0.8.0/serialized_setup_1024b_rom_length_5.bin"),
};
proofWorker.postMessage({ proverConfig, proving_params, shared_memory });
console.log("message sent to worker");
proofWorker.onmessage = (event) => {
  if (event.data.error) {
    console.error("Error from worker:", event.data.error);
  } else if (event.data.type === "log") {
    console.log(...event.data.data);
  } else {
    console.log("proof generated!", event.data);
  }
}

end();

// ./fixture/cets/notary.pub
const pubkey =
  "-----BEGIN PUBLIC KEY-----\n" +
  "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEBv36FI4ZFszJa0DQFJ3wWCXvVLFr\n" +
  "cRzMG5kaTeHGoSzDu6cFqx3uEWYpFGo6C0EOUgf+mEgbktLrXocv5yHzKg==\n" +
  "-----END PUBLIC KEY-----\n";

// const verifyResult = JSON.parse(await verify(proof, pubkey));

// console.log(verifyResult);
