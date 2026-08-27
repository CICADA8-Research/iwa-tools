// Host-based BloodHound collection for one computer over SMB2 + DCE-RPC:
//   • SAMR   — local group members  -> LocalAdmins / RemoteDesktopUsers / DcomUsers / PSRemoteUsers
//   • LSAT   — resolve member SIDs not in the directory cache (local / well-known)
//   • SRVSVC — NetrSessionEnum       -> Sessions (user -> originating computer)
//   • WKSSVC — NetrWkstaUserEnum      -> Sessions (user -> this computer)
// Each interface is collected independently; one failing (e.g. access denied)
// degrades only its own piece.

import { Smb2Client } from './smb2.js';
import { Samr, LOCAL_GROUPS } from './samr.js';
import { Lsat } from './lsat.js';
import { Srvsvc } from './srvsvc.js';
import { Wkssvc } from './wkssvc.js';
import { Winreg } from './winreg.js';

const withTimeout = (p, ms, label) => Promise.race([
  p, new Promise((_, rej) => setTimeout(() => rej(new Error(`${label} timed out`)), ms)),
]);

const notCollected = (reason, shape) => ({ Collected: false, FailureReason: reason, Results: [], ...shape });

// resolvers: { typeOf(sid), resolveUser(name)->sid, resolveComputer(name)->sid, computerSid, methods? }
// methods is a Set of collection method names (LocalAdmin, RDP, DCOM, PSRemote, Session, LoggedOn)
const METHOD_TO_EDGE = { LocalAdmin: 'LocalAdmins', RDP: 'RemoteDesktopUsers', DCOM: 'DcomUsers', PSRemote: 'PSRemoteUsers' };
export async function collectHostLocalGroups(host, creds, resolvers, { timeout = 6000, log = () => {} } = {}) {
  const { typeOf, resolveUser = () => null, resolveComputer = () => null, computerSid = null, methods = null } = resolvers;
  const has = (m) => !methods || methods.has(m);
  const c = new Smb2Client(host, 445, () => {});
  const allFail = (reason) => {
    const out = Object.fromEntries(LOCAL_GROUPS.map((g) => [g.edge, notCollected(reason)]));
    out.Sessions = notCollected(reason); out.PrivilegedSessions = notCollected(reason); out.RegistrySessions = notCollected(reason);
    return out;
  };
  try {
    await withTimeout((async () => { await c.connect(); await c.negotiate(); await c.login(creds); })(), timeout, `SMB ${host}`);
    const tid = await c.treeConnect('IPC$');
    const pipe = async (name) => c.createPipe(tid, name);
    const out = {};

    // --- SAMR: local groups (with LSAT type fallback for non-directory SIDs) ---
    const wantedGroups = LOCAL_GROUPS.filter((g) => {
      const method = Object.entries(METHOD_TO_EDGE).find(([, e]) => e === g.edge);
      return method ? has(method[0]) : true;
    });
    if (wantedGroups.length > 0) {
      try {
        const sfid = await pipe('samr');
        const samr = new Samr((b) => c.transceive(tid, sfid, b));
        const groups = await withTimeout(samr.collectLocalGroups(host), timeout, `SAMR ${host}`);
        await c.closeFile(tid, sfid);

        const unknown = [...new Set(Object.values(groups).flat())].filter((s) => typeOf(s) === 'Base');
        const lsatType = await lsatTypes(c, tid, pipe, unknown).catch(() => ({}));
        const typeFor = (sid) => (typeOf(sid) !== 'Base' ? typeOf(sid) : lsatType[sid] || 'Base');
        for (const g of LOCAL_GROUPS) {
          if (!wantedGroups.includes(g)) { out[g.edge] = notCollected('not requested'); continue; }
          out[g.edge] = { Collected: true, FailureReason: null, Results: groups[g.edge].map((sid) => ({ ObjectIdentifier: sid, ObjectType: typeFor(sid) })) };
        }
        log(`${host}: LocalAdmins ${(out.LocalAdmins.Results || []).length}, RDP ${(out.RemoteDesktopUsers.Results || []).length}.`);
      } catch (e) {
        for (const g of LOCAL_GROUPS) out[g.edge] = notCollected(e.message);
      }
    } else {
      for (const g of LOCAL_GROUPS) out[g.edge] = notCollected('not requested');
    }

    // --- Sessions: SRVSVC NetrSessionEnum + WKSSVC NetrWkstaUserEnum ---
    const collectSessions = (rows) => {
      const seen = new Set(); const res = [];
      for (const x of rows) { if (!x.UserSID || !x.ComputerSID) continue; const k = x.UserSID + '|' + x.ComputerSID; if (!seen.has(k)) { seen.add(k); res.push(x); } }
      return res;
    };
    // Sessions <- SRVSVC NetrSessionEnum (user -> the computer they connect from)
    if (has('Session')) {
      try {
        const fid = await pipe('srvsvc');
        const srv = new Srvsvc((b) => c.transceive(tid, fid, b));
        await srv.bind();
        const rows = (await withTimeout(srv.sessionEnum(host), timeout, `SRVSVC ${host}`))
          .filter((s) => s.user && !s.user.endsWith('$'))
          .map((s) => ({ UserSID: resolveUser(s.user), ComputerSID: resolveComputer(s.cname) }));
        await c.closeFile(tid, fid);
        out.Sessions = { Collected: true, FailureReason: null, Results: collectSessions(rows) };
      } catch (e) { out.Sessions = notCollected(e.message); }
    } else { out.Sessions = notCollected('not requested'); }
    // PrivilegedSessions <- WKSSVC NetrWkstaUserEnum (logged on to this computer; needs admin)
    if (has('LoggedOn')) {
      try {
        const fid = await pipe('wkssvc');
        const wks = new Wkssvc((b) => c.transceive(tid, fid, b));
        await wks.bind();
        const rows = (await withTimeout(wks.userEnum(), timeout, `WKSSVC ${host}`))
          .filter((u) => u.user && !u.user.endsWith('$'))
          .map((u) => ({ UserSID: resolveUser(u.user), ComputerSID: computerSid }));
        await c.closeFile(tid, fid);
        out.PrivilegedSessions = { Collected: true, FailureReason: null, Results: collectSessions(rows) };
      } catch (e) { out.PrivilegedSessions = notCollected(e.message); }
    } else { out.PrivilegedSessions = notCollected('not requested'); }

    // --- RegistrySessions: WINREG HKU loaded hives (user -> this computer) ---
    if (has('LoggedOn')) {
      try {
        const rfid = await openPipeRetry(c, tid, 'winreg');
        const winreg = new Winreg((b) => c.transceive(tid, rfid, b));
        const regSids = await withTimeout(winreg.registrySessions(), timeout, `WINREG ${host}`);
        await c.closeFile(tid, rfid);
        out.RegistrySessions = { Collected: true, FailureReason: null, Results: regSids.map((sid) => ({ UserSID: sid, ComputerSID: computerSid })) };
      } catch (e) {
        out.RegistrySessions = notCollected(e.message);
      }
    } else { out.RegistrySessions = notCollected('not requested'); }

    await c.close();
    return out;
  } catch (e) {
    try { await c.close(); } catch { /* ignore */ }
    log(`${host}: host collection failed — ${e.message}`);
    return allFail(e.message);
  }
}

// Open a named pipe, retrying while the backing service trigger-starts.
async function openPipeRetry(c, tid, name, attempts = 5, delay = 800) {
  for (let i = 0; ; i++) {
    try { return await c.createPipe(tid, name); }
    catch (e) { if (i >= attempts - 1) throw e; await new Promise((r) => setTimeout(r, delay)); }
  }
}

// LSAT type lookup for SIDs the directory cache couldn't classify.
async function lsatTypes(c, tid, pipe, sids) {
  if (!sids.length) return {};
  const fid = await pipe('lsarpc');
  try {
    const lsat = new Lsat((b) => c.transceive(tid, fid, b));
    await lsat.bind();
    const policy = await lsat.openPolicy();
    const named = await lsat.lookupSids(policy, sids);
    await lsat.close(policy);
    const map = {};
    for (const n of named) if (n.name) map[n.sid] = n.type;
    return map;
  } finally { await c.closeFile(tid, fid); }
}
