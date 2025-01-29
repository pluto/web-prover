import init, { prover, ProvingParamsWasm } from '../pkg/client_wasm'
import { witness } from './witness'

// Override console.log and console.error
const originalConsoleLog = console.log
const originalConsoleError = console.error

console.log = (...args) => {
  // Only postMessage, don't call original console.log
  postMessage({ type: 'log', data: args })
}

console.error = (...args) => {
  // Only postMessage, don't call original console.error
  postMessage({ type: 'error', data: args })
}

postMessage({ type: 'status', data: 'Worker running' })

var startTime, endTime

function start() {
  startTime = performance.now()
}

function end() {
  endTime = performance.now()
  var timeDiff = endTime - startTime //in ms
  // strip the ms
  timeDiff /= 1000

  // get seconds
  var seconds = Math.round(timeDiff)
  console.log('worker thread:', seconds + ' seconds')
}

function checkWorkerMemory() {
  const memoryMB = performance.memory?.jsHeapSizeLimit / (1024 * 1024) || 'unknown'
  const usedMemoryMB = performance.memory?.usedJSHeapSize / (1024 * 1024) || 'unknown'
  console.log(`Worker Memory - Limit: ${memoryMB}MB, Used: ${usedMemoryMB}MB`)
}

self.onmessage = async function (e) {
  try {
    console.log('Worker: Starting proof generation')
    const { proverConfig, proving_params, shared_memory } = e.data
    console.log('Worker: Got message data')

    self.witness = witness
    console.log('Worker: Set witness')

    console.log('Worker: Initializing...')
    await init(undefined, shared_memory)
    console.log('Worker: Initialized')

    start()
    console.log('Worker: Creating ProvingParamsWasm')
    var pp = new ProvingParamsWasm(new Uint8Array(proving_params.aux_params))
    console.log('Worker: Created ProvingParamsWasm')

    checkWorkerMemory()
    console.log('Worker: Starting prover')
    const proof = await prover(proverConfig, pp)
    checkWorkerMemory()
    console.log('Worker: Prover completed')

    console.log('sending proof back to main thread')
    end()
    postMessage({ type: 'proof', data: proof })
  } catch (error) {
    console.error('Error in worker:', error)
    console.error('Error stack:', error.stack) // Add stack trace
    postMessage({ type: 'error', data: error.message })
  }
}
