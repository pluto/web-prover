import init, {
  initThreadPool,
  prover,
  verify,
  setup_tracing_web,
} from '../../pkg/wasm_client';

export const DEFAULT_LOGGING_FILTER: string = 'info,tlsn_extension_rs=debug';

export default class TLSN {
  private startPromise: Promise<void>;
  private resolveStart!: () => void;
  private logging_filter: string;

  /**
   * Initializes a new instance of the TLSN class.
   *
   * @param logging_filter - Optional logging filter string.
   *                         Defaults to DEFAULT_LOGGING_FILTER
   */
  constructor(logging_filter: string = DEFAULT_LOGGING_FILTER) {
    this.logging_filter = logging_filter;

    this.startPromise = new Promise((resolve) => {
      this.resolveStart = resolve;
    });
    this.start();
  }

  async start() {
    // console.log('start');
    const numConcurrency = navigator.hardwareConcurrency;
    // console.log('!@# navigator.hardwareConcurrency=', numConcurrency);
    await init();
    setup_tracing_web(this.logging_filter);
    // const res = await init();
    // console.log('!@# res.memory=', res.memory);
    // 6422528 ~= 6.12 mb
    // console.log('!@# res.memory.buffer.length=', res.memory.buffer.byteLength);
    await initThreadPool(numConcurrency);
    this.resolveStart();
  }

  async waitForStart() {
    return this.startPromise;
  }

  async prove(
    url: string,
    options?: {
      method?: string;
      headers?: { [key: string]: string };
      body?: string;
      maxSentData?: number;
      maxRecvData?: number;
      maxTranscriptSize?: number;
      notaryUrl?: string;
      websocketProxyUrl?: string;
      secretHeaders?: string[];
      secretResps?: string[];
    },
  ) {
    await this.waitForStart();
    // console.log('worker', url, {
    //   ...options,
    //   notaryUrl: options?.notaryUrl,
    //   websocketProxyUrl: options?.websocketProxyUrl,
    // });
    const resProver = await prover(
      url,
      {
        ...options,
        notaryUrl: options?.notaryUrl,
        websocketProxyUrl: options?.websocketProxyUrl,
      },
      options?.secretHeaders || [],
      options?.secretResps || [],
    );
    const resJSON = JSON.parse(resProver);
    // console.log('!@# resProver,resJSON=', { resProver, resJSON });
    // console.log('!@# resAfter.memory=', resJSON.memory);
    // 1105920000 ~= 1.03 gb
    // console.log(
    //   '!@# resAfter.memory.buffer.length=',
    //   resJSON.memory?.buffer?.byteLength,
    // );

    return resJSON;
  }

  async verify(proof: any, pubkey: string) {
    await this.waitForStart();
    const raw = await verify(JSON.stringify(proof), pubkey);
    return JSON.parse(raw);
  }
}
