import TLSN from './tlsn';
import { DEFAULT_LOGGING_FILTER } from './tlsn';
import { Proof } from './types';

let _tlsn: TLSN;
const current_logging_filter = DEFAULT_LOGGING_FILTER;

async function getTLSN(logging_filter?: string): Promise<TLSN> {
  const logging_filter_changed =
    logging_filter && logging_filter == current_logging_filter;

  if (!logging_filter_changed && _tlsn) return _tlsn;
  // @ts-ignore
  if (logging_filter) _tlsn = await new TLSN(logging_filter);
  else _tlsn = await new TLSN();
  return _tlsn;
}

/**
 * If you want to change the default logging filter, call this method before calling prove or verify
 * For the filter syntax consult: https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html#example-syntax
 * @param logging_filter
 */
export const set_logging_filter = async (logging_filter: string) => {
  getTLSN(logging_filter);
};

export const prove = async (
  url: string,
  options: {
    notaryUrl: string;
    websocketProxyUrl: string;
    method?: string;
    headers?: { [key: string]: string };
    body?: string;
    maxSentData?: number;
    maxRecvData?: number;
    maxTranscriptSize?: number;
    secretHeaders?: string[];
    secretResps?: string[];
  },
): Promise<Proof> => {
  const {
    method,
    headers = {},
    body = '',
    maxSentData,
    maxRecvData,
    maxTranscriptSize = 16384,
    notaryUrl,
    websocketProxyUrl,
    secretHeaders,
    secretResps,
  } = options;

  const tlsn = await getTLSN();

  headers['Host'] = new URL(url).host;
  headers['Connection'] = 'close';

  const proof = await tlsn.prove(url, {
    method,
    headers,
    body,
    maxSentData,
    maxRecvData,
    maxTranscriptSize,
    notaryUrl,
    websocketProxyUrl,
    secretHeaders,
    secretResps,
  });

  return {
    ...proof,
    notaryUrl,
  };
};

export const verify = async (
  proof: Proof,
  publicKeyOverride?: string,
): Promise<{
  time: number;
  sent: string;
  recv: string;
  notaryUrl: string;
}> => {
  const publicKey =
    publicKeyOverride || (await fetchPublicKeyFromNotary(proof.notaryUrl));
  const tlsn = await getTLSN();
  const result = await tlsn.verify(proof, publicKey);
  return {
    ...result,
    notaryUrl: proof.notaryUrl,
  };
};

async function fetchPublicKeyFromNotary(notaryUrl: string) {
  const res = await fetch(notaryUrl + '/info');
  const json: any = await res.json();
  if (!json.publicKey) throw new Error('invalid response');
  return json.publicKey;
}
