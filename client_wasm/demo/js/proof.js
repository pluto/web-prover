import init, { prover, setup_tracing } from "../pkg/client_wasm";

let wasmInitialized = false;

async function initializeWasm() {
    if (!wasmInitialized) {
        await init();
        setup_tracing("debug,tlsn_extension_rs=debug");
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
        await initializeWasm();
        start();
        const proof = await prover(e.data);
        console.log("sending proof back to main thread");
        end();
        postMessage({ type: 'proof', data: proof });
    } catch (error) {
        console.error("Error in worker:", error);
        postMessage({ type: 'error', data: error.message });
    }
}