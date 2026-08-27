// MC-NBFSE = NBFS/NBFX with an in-band session dictionary prepended:
//   [dictSize: mbi][dict string table][NBFX document]
// On send we use a BLANK dictionary (size 0) — the documented bypass that lets
// us avoid maintaining a shared session dictionary with the server. On receive
// we parse the server's in-band dictionary (odd-indexed strings) so the NBFX
// decoder can resolve dictionary references.

import { parseXml, serializeXml } from './xml.js';
import { encodeRecords, decodeRecords, mbiBytes } from './nbfx.js';

const dec = new TextDecoder();

// XML string -> NBFSE bytes (blank in-band dictionary).
export function encodeNbfse(xml) {
  const records = encodeRecords(parseXml(xml));
  const out = new Uint8Array(1 + records.length);
  out[0] = 0x00;            // empty dictionary: size 0
  out.set(records, 1);
  return out;
}

// NBFSE bytes -> { tree, session, xml }. `xml` is a lazy getter: serializing the
// whole record tree back to a string is only needed for fault diagnostics, so we
// avoid doing it for every (potentially multi-MB) Pull response page.
export function decodeNbfse(buf) {
  let p = 0;
  // read dictSize (mbi)
  let size = 0, sh = 0, b;
  do { b = buf[p++]; size |= (b & 0x7f) << sh; sh += 7; } while (b & 0x80);
  const session = {};
  const end = p + size;
  let idx = 1;
  while (p < end) {
    let slen = 0, s2 = 0, c;
    do { c = buf[p++]; slen |= (c & 0x7f) << s2; s2 += 7; } while (c & 0x80);
    session[idx] = dec.decode(buf.subarray(p, p + slen));
    p += slen; idx += 2;
  }
  const tree = decodeRecords(buf.subarray(end), session);
  const result = { tree, session };
  Object.defineProperty(result, 'xml', { enumerable: true, get: () => serializeXml(tree) });
  return result;
}

export { mbiBytes };
