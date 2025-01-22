import init, { initThreadPool, setup_tracing } from '/pkg/client_wasm.js'

onmessage = async (e) => {
  try {
    const { concurrency, wasm_bytes, shared_memory, proving_params } = e.data
    if (!shared_memory || !wasm_bytes) {
      throw new Error('Missing memory or wasmBytes from main thread!')
    }
    await init(wasm_bytes, shared_memory)

    postMessage('worker done')
  } catch (err) {
    postMessage({ type: 'worker-error', error: err.toString() })
  }
}
