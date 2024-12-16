import init, { prover, setup_tracing, initThreadPool, ProvingParamsWasm } from "../pkg/client_wasm";
import { witness } from "./witness";

let wasmInitialized = false;
let sharedMemory = null;
const numConcurrency = navigator.hardwareConcurrency;

async function initializeWasm(memory) {
    if (!wasmInitialized) {
        // Create a WebAssembly.Memory object
        const memory = new WebAssembly.Memory({
            initial: 16384, // 256 pages = 16MB
            maximum: 65536, // 1024 pages = 64MB
            shared: true, // Enable shared memory
        });
        await init(undefined, memory);
        setup_tracing("debug,tlsn_extension_rs=debug");
        await initThreadPool(numConcurrency);
        wasmInitialized = true;
    }
}

// Override console.log and console.error
const originalConsoleLog = console.log;
const originalConsoleError = console.error;

console.log = (...args) => {
    originalConsoleLog(...args);
    postMessage({ type: 'log', data: args });
};

console.error = (...args) => {
    originalConsoleError(...args);
    postMessage({ type: 'error', data: args });
};

postMessage({ type: 'status', data: 'Worker running' });

var startTime, endTime;

function start() {
    startTime = performance.now();
}

function end() {
    endTime = performance.now();
    var timeDiff = endTime - startTime; //in ms
    // strip the ms
    timeDiff /= 1000;

    // get seconds
    var seconds = Math.round(timeDiff);
    console.log("worker thread:", seconds + " seconds");
}

self.onmessage = async function (e) {
    try {
        const { proverConfig, proving_params, memory } = e.data;
        sharedMemory = memory;
        await initializeWasm(sharedMemory);
        start();
        var pp = new ProvingParamsWasm(
            new Uint8Array(proving_params.aux_params),
        );
        console.log("proving params", proving_params);
        const proof = await prover(proverConfig, pp);
        console.log("sending proof back to main thread");
        end();
        postMessage({ type: 'proof', data: proof });
    } catch (error) {
        console.error("Error in worker:", error);
        postMessage({ type: 'error', data: error.message });
    }
}