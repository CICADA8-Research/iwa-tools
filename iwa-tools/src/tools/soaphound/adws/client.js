// High-level ADWS client: opens one NMF/NNS duplex session to the Enumeration
// endpoint, then runs WS-Enumeration (Enumerate + Pull loop) and decodes the
// NBFSE responses into plain { dn, className, attributes } rows. Mirrors SoaPy
// adws.py at the operational level.

import { Connection } from '../net/socket.js';
import { Nns } from '../nns/nns.js';
import { KerberosClient, KdcSocketTransport } from '../kerberos/client.js';
import { ETYPE } from '../kerberos/constants.js';
import * as nmf from '../nmf/nmf.js';
import { encodeNbfse, decodeNbfse } from '../encoder/nbfse.js';
import { enumerateXml, pullXml, domainToBaseDN } from '../soap/templates.js';

const uuid = () => (globalThis.crypto?.randomUUID
  ? globalThis.crypto.randomUUID()
  : 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = Math.floor(globalThis.crypto.getRandomValues(new Uint8Array(1))[0] / 16);
      return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
    }));

function hexToBytes(h) {
  const clean = h.replace(/[^0-9a-fA-F]/g, '');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

// Resolve an ADWS service ticket from an imported { tgts, serviceTickets } bundle
// (parsed ccache/kirbi): a stored ticket for the same service is pass-the-ticket
// (no KDC contact); otherwise a stored TGT is exchanged for one via TGS.
async function serviceTicketFromImport(ticket, { host, kdc, spn, log }) {
  const wantService = spn.split('/')[0].toLowerCase();
  const realmOf = (t) => (t.realm || t.crealm || '').replace(/\.$/, '');
  const svc = (ticket.serviceTickets || []).find((t) => (t.spn || '').split('/')[0].toLowerCase() === wantService);
  if (svc) {
    log(`ADWS: using imported ${svc.spn} service ticket (pass-the-ticket — no password).`);
    const clockOffsetMs = await kdcClockOffsetMs(kdc || host, svc.cname?.[0], realmOf(svc), log);
    return { ...svc, spn: svc.spn || spn, clockOffsetMs };
  }
  const tgt = (ticket.tgts || [])[0];
  if (!tgt) throw new Error(`imported ticket has no ${wantService} service ticket and no TGT`);
  log(`ADWS: using imported TGT for ${tgt.cname.join('/')}@${tgt.crealm}; requesting ${spn} …`);
  const transport = new KdcSocketTransport(kdc || host, 88, log);
  await transport.connect();
  try { const krb = new KerberosClient(transport, log); await krb.calibrateClock(tgt.cname?.[0], realmOf(tgt)); return await krb.getTGS(tgt, { spn }); }
  finally { await transport.close(); }
}

// Best-effort KDC time sync (own short-lived transport): the imported ticket's
// AP-REQ needs a timestamp within the DC's skew window even on an unsynced box.
async function kdcClockOffsetMs(kdcHost, username, realm, log) {
  if (!realm) return 0;
  try {
    const transport = new KdcSocketTransport(kdcHost, 88, log);
    await transport.connect();
    try { return await new KerberosClient(transport, log).calibrateClock(username, realm); }
    finally { await transport.close(); }
  } catch { return 0; }
}

export class AdwsClient {
  constructor(log = () => {}) {
    this._log = log;
    this._conn = null;
    this._nns = null;
    this.fqdn = null;
    this.port = 9389;
  }

  async connect(host, port, creds, { fqdn, connection } = {}) {
    this.port = port || 9389;
    this.fqdn = fqdn || host;
    const via = `net.tcp://${this.fqdn}:${this.port}/ActiveDirectoryWebServices/Windows/Enumeration`;

    // For Kerberos, acquire an ADWS service ticket up front (unless the caller
    // already supplied one — used by the offline/live test harness). The KDC
    // talks over its own socket on 88.
    if (creds.authMethod === 'kerberos' && !creds.serviceTicket) {
      // Imported ccache/kirbi (console --ticket): a stored HOST/… ticket is
      // pass-the-ticket (no KDC); a stored TGT → one TGS for the ADWS SPN.
      creds.serviceTicket = creds.ticket
        ? await serviceTicketFromImport(creds.ticket, { host, kdc: creds.kdc, spn: creds.spn || `HOST/${this.fqdn}`, log: this._log })
        : await this._getServiceTicket(creds, host);
    }

    // `connection` lets a test harness inject a pre-connected transport (e.g. a
    // Node net socket); otherwise open a Direct Sockets TCPSocket.
    this._conn = connection || new Connection(this._log);
    if (!connection) await this._conn.connect(host, this.port);

    // Cleartext preamble + upgrade.
    await this._conn.write(nmf.preamble(via));
    await this._conn.write(nmf.upgradeRequest('application/negotiate'));
    const r = await this._conn.readExact(1);
    if (r[0] !== nmf.REC.UPGRADE_RESPONSE) throw new Error(`ADWS: expected UpgradeResponse, got 0x${r[0].toString(16)}`);

    // Authenticated, sealed channel.
    this._nns = new Nns(this._conn, this._log);
    await this._nns.authenticate(creds);

    // Sealed PreambleEnd -> PreambleAck.
    await this._nns.secureWrite(nmf.preambleEnd());
    const ack = await this._nns.secureReadByte();
    if (ack !== nmf.REC.PREAMBLE_ACK) throw new Error(`ADWS: expected PreambleAck, got 0x${ack.toString(16)}`);
    this._log('ADWS session established.');
  }

  // Acquire a TGT + ADWS service ticket. The ADWS NegotiateStream authenticates
  // to the DC's host SPN by default (HOST/<fqdn>).
  async _getServiceTicket(creds, host) {
    const transport = new KdcSocketTransport(creds.kdc || host, 88, this._log);
    await transport.connect();
    try {
      const krb = new KerberosClient(transport, this._log);
      const id = { username: creds.user, realm: creds.domain };
      if (creds.hash) { id.key = hexToBytes(creds.hash); id.etype = ETYPE.RC4_HMAC; }
      else id.password = creds.password;
      const tgt = await krb.getTGT(id);
      return await krb.getTGS(tgt, { spn: creds.spn || `HOST/${this.fqdn}` });
    } finally {
      await transport.close();
    }
  }

  // Send one SOAP message (NBFSE in a SizedEnvelope) and read one response.
  async _exchange(xml) {
    const payload = encodeNbfse(xml);
    await this._nns.secureWrite(nmf.sizedEnvelope(payload));
    return this._readMessage();
  }

  async _readMessage() {
    const t = await this._nns.secureReadByte();
    if (t === nmf.REC.END) return null;
    if (t === nmf.REC.FAULT) {
      const size = await nmf.decodeVarint(() => this._nns.secureReadByte());
      const body = await this._nns.secureReadExact(size);
      throw new Error('ADWS NMF fault: ' + new TextDecoder().decode(body));
    }
    if (t !== nmf.REC.SIZED_ENVELOPE) throw new Error(`ADWS: unexpected record 0x${t.toString(16)}`);
    const size = await nmf.decodeVarint(() => this._nns.secureReadByte());
    const payload = await this._nns.secureReadExact(size);
    return decodeNbfse(payload);
  }

  // Open an enumeration context for a query (optionally with per-attribute
  // range hints for range retrieval).
  async _enumerate(baseDN, filter, attributes, rangeHints) {
    const resp = await this._exchange(enumerateXml({
      fqdn: this.fqdn, port: this.port, uuid: uuid(), query: filter, baseObject: baseDN, attributes, rangeHints,
    }));
    checkFault(resp);
    const ctxEl = findFirst(resp.tree, 'EnumerationContext');
    return ctxEl ? textOf(ctxEl) : null;
  }

  // Pull every object out of an enumeration context (paged until EndOfSequence).
  async *_pullObjects(enumCtx, label = '') {
    let more = true, page = 0;
    while (more) {
      page++;
      const resp = await this._exchange(pullXml({ fqdn: this.fqdn, port: this.port, uuid: uuid(), enumCtx }));
      checkFault(resp);
      let n = 0;
      for (const itemsEl of findAll(resp.tree, 'Items')) {
        for (const obj of itemsEl.children) {
          if (obj.kind !== 'el') continue;
          n++;
          yield parseObject(obj);
        }
      }
      more = !findFirst(resp.tree, 'EndOfSequence');
      if (label) this._log(`${label} pull page ${page}: ${n} object(s)${more ? '' : ' (end)'}.`);
    }
  }

  // Run a full query: Enumerate then Pull until EndOfSequence. Multi-valued
  // attributes that the server truncates (RangeLow/RangeHigh markers) are
  // completed via range retrieval before each object is yielded.
  async *query({ baseDN, filter = '(objectClass=*)', attributes = [], expandRanges = true }) {
    const enumCtx = await this._enumerate(baseDN, filter, attributes);
    if (!enumCtx) throw new Error('ADWS: no EnumerationContext in Enumerate response');
    this._log('Enumeration context acquired; pulling …');
    for await (const obj of this._pullObjects(enumCtx, 'main')) {
      if (expandRanges && obj.ranges && Object.keys(obj.ranges).length) {
        await this._expandRanges(obj);
      }
      yield obj;
    }
  }

  // Complete each ranged attribute of `obj` by re-querying the object for the
  // remaining value windows until the server reports the final range (RangeHigh
  // "*"), appending values in place. [MS-ADTS] incremental retrieval.
  async _expandRanges(obj) {
    for (const attr of Object.keys(obj.ranges)) {
      let nextLow = obj.ranges[attr].high + 1;
      const seen = obj.attributes[attr] ? obj.attributes[attr].length : 0;
      let total = seen;
      for (let guard = 0; guard < 100000; guard++) {
        const ctx = await this._enumerate(obj.dn, '(objectClass=*)', [attr], { [attr]: { low: nextLow, high: '*' } });
        if (!ctx) break;
        let merged = 0, nextHigh = null;
        for await (const sub of this._pullObjects(ctx)) {
          if (sub.dn && obj.dn && sub.dn.toUpperCase() !== obj.dn.toUpperCase()) continue;
          const vals = sub.attributes[attr] || [];
          if (vals.length) {
            obj.attributes[attr] = (obj.attributes[attr] || []).concat(vals);
            merged += vals.length;
          }
          const r = sub.ranges && sub.ranges[attr];
          if (r && Number.isFinite(r.high)) nextHigh = r.high; // more remain
        }
        total += merged;
        if (merged === 0 || nextHigh === null) break; // final window reached
        nextLow = nextHigh + 1;
      }
      this._log(`Range-retrieved ${attr} for ${obj.dn}: ${total} value(s).`);
    }
    obj.ranges = {};
  }

  async close() {
    try { await this._conn?.close(); } catch { /* ignore */ }
  }
}

export { domainToBaseDN };

// ---- response tree helpers -------------------------------------------------
function findAll(nodes, name, out = []) {
  for (const n of nodes) {
    if (n.kind !== 'el') continue;
    if (n.name === name) out.push(n);
    if (n.children) findAll(n.children, name, out);
  }
  return out;
}
function findFirst(nodes, name) {
  for (const n of nodes) {
    if (n.kind !== 'el') continue;
    if (n.name === name) return n;
    const c = n.children && findFirst(n.children, name);
    if (c) return c;
  }
  return null;
}
function textOf(node) {
  let s = '';
  for (const c of node.children || []) if (c.kind === 'text') s += c.value;
  return s;
}

// An object element (addata:user, addata:group, …): children are attribute
// elements, each holding ad:value children. Attribute elements may carry
// RangeLow/RangeHigh markers when the server truncated a large multi-valued
// attribute; a numeric RangeHigh signals more values are available.
function parseObject(obj) {
  const attributes = {};
  const ranges = {};
  for (const attrEl of obj.children) {
    if (attrEl.kind !== 'el') continue;
    if (attrEl.name === 'objectReferenceProperty') {
      attributes.objectReferenceProperty = [textOf(attrEl)];
      continue;
    }
    const vals = [];
    let hasValueChild = false;
    for (const v of attrEl.children) {
      if (v.kind === 'el' && v.name === 'value') { hasValueChild = true; vals.push(textOf(v)); }
    }
    attributes[attrEl.name] = hasValueChild ? vals : [textOf(attrEl)];

    let low, high;
    for (const a of attrEl.attrs || []) {
      if (a.name === 'RangeLow') low = a.value;
      if (a.name === 'RangeHigh') high = a.value;
    }
    // A numeric RangeHigh means this window is partial; "*" means it is the last.
    if (high !== undefined && high !== '*') {
      ranges[attrEl.name] = { low: Number(low || 0), high: Number(high) };
    }
  }
  return {
    className: obj.name,
    dn: attributes.distinguishedName ? attributes.distinguishedName[0] : null,
    attributes,
    ranges,
  };
}

function checkFault(resp) {
  if (!resp) return;
  const fault = findFirst(resp.tree, 'Fault');
  if (fault) {
    const reason = findFirst(resp.tree, 'Text') || findFirst(resp.tree, 'Reason');
    throw new Error('ADWS SOAP fault: ' + (reason ? textOf(reason) : resp.xml.slice(0, 500)));
  }
}
