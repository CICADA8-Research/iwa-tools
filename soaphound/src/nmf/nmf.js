// .NET Message Framing Protocol (MC-NMF). ADWS speaks NMF over TCP 9389: a
// cleartext preamble (version/mode/via/encoding) then an "upgrade" to a security
// negotiation (handled by nns.js); after the upgrade the framing continues over
// the sealed stream with PreambleEnd/Ack and SizedEnvelope data records.
//
// This module only builds/parses records and the 7-bit varint sizes. The
// transport sequencing lives in adws/client.js, which decides which records go
// on the raw socket (preamble) vs the sealed NNS stream (PreambleEnd onward).

const enc = new TextEncoder();

export const REC = {
  VERSION: 0x00,
  MODE: 0x01,
  VIA: 0x02,
  KNOWN_ENCODING: 0x03,
  SIZED_ENVELOPE: 0x06,
  END: 0x07,
  FAULT: 0x08,
  UPGRADE_REQUEST: 0x09,
  UPGRADE_RESPONSE: 0x0a,
  PREAMBLE_ACK: 0x0b,
  PREAMBLE_END: 0x0c,
};

export const MODE_DUPLEX = 0x02;
// 0x08 = application/soap+msbinsession1 (MC-NBFSE, binary SOAP with in-band dict).
export const ENCODING_NBFSE = 0x08;

// 7-bit varint ("multi-byte int"): low 7 bits per byte, high bit = continuation.
export function encodeVarint(n) {
  const out = [];
  let v = n >>> 0;
  do {
    let b = v & 0x7f;
    v >>>= 7;
    if (v) b |= 0x80;
    out.push(b);
  } while (v);
  return Uint8Array.from(out);
}

// Decode a varint by pulling one byte at a time from an async byte source
// `readByte()` that resolves to a number.
export async function decodeVarint(readByte) {
  let shift = 0, result = 0, b;
  do {
    b = await readByte();
    result |= (b & 0x7f) << shift;
    shift += 7;
  } while (b & 0x80);
  return result >>> 0;
}

function concat(arrays) {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

// A length-prefixed string record (Via, UpgradeRequest): type + varint(len) + utf8.
function stringRecord(type, str) {
  const s = enc.encode(str);
  return concat([Uint8Array.of(type), encodeVarint(s.length), s]);
}

// The cleartext preamble for a duplex NBFSE session to `via`
// (net.tcp://host:9389/ActiveDirectoryWebServices/Windows/<endpoint>).
export function preamble(via) {
  return concat([
    Uint8Array.of(REC.VERSION, 0x01, 0x00),         // version 1.0
    Uint8Array.of(REC.MODE, MODE_DUPLEX),           // duplex
    stringRecord(REC.VIA, via),                     // via
    Uint8Array.of(REC.KNOWN_ENCODING, ENCODING_NBFSE),
  ]);
}

export function upgradeRequest(upgrade = 'application/negotiate') {
  return stringRecord(REC.UPGRADE_REQUEST, upgrade);
}

export const preambleEnd = () => Uint8Array.of(REC.PREAMBLE_END);
export const endRecord = () => Uint8Array.of(REC.END);

// SizedEnvelope: type + varint(size) + payload.
export function sizedEnvelope(payload) {
  return concat([Uint8Array.of(REC.SIZED_ENVELOPE), encodeVarint(payload.length), payload]);
}
