import { parseTargets } from './net/targets.js';
import {
  smbAuth, smbShares, smbSessions, smbLoggedOn, smbLocalGroups,
  smbUsers, smbGroups, smbRegSessions, smbExec, smbSpider, smbGet, smbPut,
  smbRidBrute, smbSamDump, smbGpp, smbLsaDump, smbDcsync,
  smbSigning, smbRelay, smbSpooler, smbPetitpotam, smbWebdav,
  smbDfscoerce, smbShadowcoerce, smbCoerce, smbGhost, smbZerologon, smbPrintnightmare,
  smbPasswd, smbAtExec,
  smbSvcStart, smbSvcStop, smbSvcStatus, smbSvcCreate, smbSvcDelete,
  smbNtds, smbEnumAv, smbOsInfo, smbFiles, smbEternalBlue, smbPipes, smbDialect,
  smbGoldenTicket, smbSilverTicket, smbS4u, smbDpapi, smbWmiExec, smbEpm,
} from './protocols/smb.js';
import {
  ldapAuth, ldapUsers, ldapGroups, ldapComputers, ldapDCs, ldapSpns,
  ldapKerberoast, ldapAsrep, ldapPassPol, ldapLaps, ldapGmsa,
  ldapDelegation, ldapTrusts, ldapAdcs, ldapMaq, ldapDesc, ldapAdmins,
  ldapFgpp, ldapSubnets, ldapSearch, ldapSigning,
  ldapOUs, ldapGPOs, ldapDNS, ldapDACL, ldapNoPac, ldapShadowCreds,
  ldapAddComputer, ldapRbcd, ldapDelComputer, ldapChangePwd,
  ldapRbcdClear, ldapDisableUser, ldapEnableUser,
  ldapAddGroupMember, ldapRemoveGroupMember, ldapSetSPN, ldapClearSPN,
  ldapSetDesc, ldapSetDontReqPreauth, ldapClearDontReqPreauth,
  ldapGetSid, ldapPasswordNotReqd, ldapNeverExpires, ldapObsolete,
  ldapLocked, ldapDisabled, ldapFuncLevel, ldapRODC, ldapPwdExpired,
  ldapProtectedUsers, ldapSensitive, ldapRecon,
  ldapExchange, ldapSccm, ldapStaleComputers, ldapAdminCount, ldapServiceAccounts,
  ldapTrustedDeleg, ldapSidhist, ldapMachineQuota, ldapDnsZones, ldapSchemaVersion, ldapLargeGroups,
  ldapEmptyPwd, ldapPreWin2k, ldapOldPasswords, ldapRecycleBin,
  ldapEnterpriseAdmins, ldapSites, ldapManagedBy, ldapDnsRecords,
} from './protocols/ldap.js';
import {
  winrmAuth, winrmExec, winrmPs, winrmSam, winrmLsa,
  winrmSysinfo, winrmIpconfig, winrmWhoami, winrmProcs,
  winrmServices, winrmNetstat, winrmAv, winrmGet, winrmPut,
  winrmRegQuery, winrmEnv, winrmUsers, winrmShares, winrmDisk, winrmSoftware, winrmTasks,
  winrmFirewall, winrmDomainInfo, winrmEvents, winrmPrivs, winrmPatches,
  winrmStartup, winrmDrivers, winrmAuditPol, winrmDefender, winrmLocalAdmins,
  winrmPipes, winrmAutorun, winrmTokenPrivs,
  winrmLsass, winrmAppLocker, winrmBitlocker, winrmCredVault, winrmDotnet, winrmWifi,
  winrmWmi, winrmWmiQuery, winrmSecrets, winrmUac, winrmPowershellHistory,
} from './protocols/winrm.js';
import {
  mssqlAuth, mssqlExec, mssqlQuery, mssqlUsers, mssqlDbs, mssqlPrivesc, mssqlLinks, mssqlOpenquery,
  mssqlGet, mssqlPut, mssqlOle, mssqlClr,
  mssqlStealHash, mssqlImpersonate, mssqlWhoami,
  mssqlTables, mssqlColumns, mssqlSearch, mssqlSysinfo, mssqlLogins,
  mssqlBackups, mssqlJobs, mssqlAudit, mssqlCredentials,
  mssqlTriggers, mssqlProcs, mssqlDbSize, mssqlBrute,
} from './protocols/mssql.js';
import { ftpAuth, ftpAnon, ftpLs, ftpGet, ftpPut, ftpBrute, ftpBanner, ftpSpider, ftpWrite } from './protocols/ftp.js';
import {
  sshAuth, sshExec, sshSysinfo, sshWhoami, sshProcs, sshNetstat,
  sshShadow, sshKeys, sshSudo, sshCrontab, sshSuid, sshCapabilities,
  sshEnv, sshWritable, sshInterfaces, sshBrute, sshBanner, sshRecon,
  sshDocker, sshUsers, sshPortscan, sshHistory, sshConfigs, sshScreens,
  sshMounts, sshFirewall, sshPackages, sshSecrets,
} from './protocols/ssh.js';
import { rdpScreen, rdpBlueKeep, rdpNla, rdpBanner } from './protocols/rdp.js';
import { vncScreen, vncBrute, vncAuth, vncBanner } from './protocols/vnc.js';

// DOM handles are optional. When nxc.js is imported by the iwa-tools console
// (which drives it through `run(argv, io)` below) `document` may not have
// these IDs — every DOM reference in this file is guarded so the module can
// run headless.
const DOM = typeof document !== 'undefined';
const terminal = DOM ? document.getElementById('terminal') : null;
const input = DOM ? document.getElementById('input') : null;
const hintBox = DOM ? document.getElementById('hint') : null;
const stTargets = DOM ? document.getElementById('st-targets') : null;
const stOk = DOM ? document.getElementById('st-ok') : null;
const stFail = DOM ? document.getElementById('st-fail') : null;
const statusEl = DOM ? document.getElementById('status') : null;

// When the console-integrated `run(argv, io)` path is active, `CURRENT_IO`
// routes every emit/writeLine/writeHtml to the caller instead of the DOM.
let CURRENT_IO = null;

let running = false;
let abortCtrl = null;
let okCount = 0;
let failCount = 0;
const history = [];
let histIdx = -1;

const DISPATCH = {
  smb: {
    auth: smbAuth, shares: smbShares, sessions: smbSessions,
    'logged-on': smbLoggedOn, 'local-groups': smbLocalGroups,
    users: smbUsers, groups: smbGroups, 'reg-sessions': smbRegSessions,
    exec: smbExec, spider: smbSpider, get: smbGet, put: smbPut,
    'rid-brute': smbRidBrute,
    sam: smbSamDump,
    gpp: smbGpp,
    lsa: smbLsaDump,
    dcsync: smbDcsync,
    signing: smbSigning,
    relay: smbRelay,
    spooler: smbSpooler,
    petitpotam: smbPetitpotam,
    webdav: smbWebdav,
    dfscoerce: smbDfscoerce,
    shadowcoerce: smbShadowcoerce,
    coerce: smbCoerce,
    smbghost: smbGhost,
    zerologon: smbZerologon,
    printnightmare: smbPrintnightmare,
    passwd: smbPasswd,
    atexec: smbAtExec,
    'svc-start': smbSvcStart,
    'svc-stop': smbSvcStop,
    'svc-status': smbSvcStatus,
    'svc-create': smbSvcCreate,
    'svc-delete': smbSvcDelete,
    ntds: smbNtds,
    'enum-av': smbEnumAv,
    'os-info': smbOsInfo,
    files: smbFiles,
    'ms17-010': smbEternalBlue,
    pipes: smbPipes,
    dialect: smbDialect,
    'golden-ticket': smbGoldenTicket,
    'silver-ticket': smbSilverTicket,
    s4u: smbS4u,
    dpapi: smbDpapi,
    wmi: smbWmiExec,
    epm: smbEpm,
  },
  ldap: {
    auth: ldapAuth, users: ldapUsers, groups: ldapGroups,
    computers: ldapComputers, dcs: ldapDCs, spns: ldapSpns,
    kerberoast: ldapKerberoast, asrep: ldapAsrep, 'pass-pol': ldapPassPol,
    laps: ldapLaps, gmsa: ldapGmsa, delegation: ldapDelegation,
    trusts: ldapTrusts, adcs: ldapAdcs, maq: ldapMaq, desc: ldapDesc,
    admins: ldapAdmins, fgpp: ldapFgpp, subnets: ldapSubnets, search: ldapSearch,
    signing: ldapSigning,
    ous: ldapOUs,
    gpos: ldapGPOs,
    dns: ldapDNS,
    dacl: ldapDACL,
    nopac: ldapNoPac,
    'shadow-creds': ldapShadowCreds,
    'add-computer': ldapAddComputer,
    'del-computer': ldapDelComputer,
    rbcd: ldapRbcd,
    'rbcd-clear': ldapRbcdClear,
    changepwd: ldapChangePwd,
    'disable-user': ldapDisableUser,
    'enable-user': ldapEnableUser,
    'add-member': ldapAddGroupMember,
    'rm-member': ldapRemoveGroupMember,
    'set-spn': ldapSetSPN,
    'clear-spn': ldapClearSPN,
    'set-desc': ldapSetDesc,
    'set-asrep': ldapSetDontReqPreauth,
    'clear-asrep': ldapClearDontReqPreauth,
    'get-sid': ldapGetSid,
    'passnotreqd': ldapPasswordNotReqd,
    'never-expires': ldapNeverExpires,
    'obsolete': ldapObsolete,
    'locked': ldapLocked,
    'disabled': ldapDisabled,
    'func-level': ldapFuncLevel,
    rodc: ldapRODC,
    'pwd-expired': ldapPwdExpired,
    'protected-users': ldapProtectedUsers,
    sensitive: ldapSensitive,
    recon: ldapRecon,
    exchange: ldapExchange,
    sccm: ldapSccm,
    'stale-computers': ldapStaleComputers,
    'admin-count': ldapAdminCount,
    'svc-accounts': ldapServiceAccounts,
    'trusted-deleg': ldapTrustedDeleg,
    sidhist: ldapSidhist,
    'machine-quota': ldapMachineQuota,
    'dns-zones': ldapDnsZones,
    'schema-version': ldapSchemaVersion,
    'large-groups': ldapLargeGroups,
    'empty-pwd': ldapEmptyPwd,
    'pre-win2k': ldapPreWin2k,
    'old-passwords': ldapOldPasswords,
    'recycle-bin': ldapRecycleBin,
    'enterprise-admins': ldapEnterpriseAdmins,
    sites: ldapSites,
    'managed-by': ldapManagedBy,
    'dns-records': ldapDnsRecords,
  },
  winrm: {
    auth: winrmAuth, exec: winrmExec, ps: winrmPs,
    'local-users': winrmSam, 'local-groups': winrmLsa, sysinfo: winrmSysinfo,
    ipconfig: winrmIpconfig, whoami: winrmWhoami, procs: winrmProcs,
    services: winrmServices, netstat: winrmNetstat, av: winrmAv,
    get: winrmGet, put: winrmPut,
    'reg-query': winrmRegQuery, env: winrmEnv, users: winrmUsers,
    shares: winrmShares, disk: winrmDisk, software: winrmSoftware, tasks: winrmTasks,
    firewall: winrmFirewall, 'domain-info': winrmDomainInfo,
    events: winrmEvents, privs: winrmPrivs, patches: winrmPatches,
    startup: winrmStartup, drivers: winrmDrivers, 'audit-pol': winrmAuditPol,
    defender: winrmDefender, 'local-admins': winrmLocalAdmins,
    pipes: winrmPipes, autorun: winrmAutorun, 'token-privs': winrmTokenPrivs,
    lsass: winrmLsass, applocker: winrmAppLocker, bitlocker: winrmBitlocker,
    'cred-vault': winrmCredVault, dotnet: winrmDotnet, wifi: winrmWifi,
    wmi: winrmWmi, 'wmi-query': winrmWmiQuery,
    secrets: winrmSecrets, uac: winrmUac, 'ps-history': winrmPowershellHistory,
  },
  mssql: {
    auth: mssqlAuth, exec: mssqlExec, query: mssqlQuery,
    users: mssqlUsers, dbs: mssqlDbs, privesc: mssqlPrivesc, links: mssqlLinks, openquery: mssqlOpenquery,
    get: mssqlGet, put: mssqlPut, ole: mssqlOle, clr: mssqlClr,
    'steal-hash': mssqlStealHash, impersonate: mssqlImpersonate, whoami: mssqlWhoami,
    tables: mssqlTables, columns: mssqlColumns, 'mssql-search': mssqlSearch,
    sysinfo: mssqlSysinfo, logins: mssqlLogins,
    backups: mssqlBackups, jobs: mssqlJobs, audit: mssqlAudit, credentials: mssqlCredentials,
    triggers: mssqlTriggers, procs: mssqlProcs, 'db-size': mssqlDbSize, brute: mssqlBrute,
  },
  ftp: { auth: ftpAuth, anon: ftpAnon, ls: ftpLs, get: ftpGet, put: ftpPut, brute: ftpBrute, banner: ftpBanner, spider: ftpSpider, 'write-check': ftpWrite },
  rdp: { screen: rdpScreen, bluekeep: rdpBlueKeep, nla: rdpNla, banner: rdpBanner },
  vnc: { screen: vncScreen, brute: vncBrute, auth: vncAuth, banner: vncBanner },
  ssh: {
    auth: sshAuth, exec: sshExec, sysinfo: sshSysinfo,
    whoami: sshWhoami, procs: sshProcs, netstat: sshNetstat,
    shadow: sshShadow, keys: sshKeys, sudo: sshSudo,
    crontab: sshCrontab, suid: sshSuid, capabilities: sshCapabilities,
    env: sshEnv, writable: sshWritable, interfaces: sshInterfaces,
    brute: sshBrute, banner: sshBanner, recon: sshRecon,
    docker: sshDocker, users: sshUsers, portscan: sshPortscan,
    history: sshHistory, configs: sshConfigs, screens: sshScreens,
    mounts: sshMounts, firewall: sshFirewall, packages: sshPackages, secrets: sshSecrets,
  },
};

function emit(level, proto, host, label, detail) {
  if (level === 'ok') okCount++;
  if (level === 'err') failCount++;
  if (CURRENT_IO && CURRENT_IO.emit) { CURRENT_IO.emit(level, proto, host, label, detail); return; }
  if (!terminal) return;
  const div = document.createElement('div');
  div.className = `line ${level}`;
  const protoHtml = proto ? `<span class="proto ${proto}">${proto.toUpperCase()}</span>` : '';
  const hostHtml = host ? `<span class="host">${host}</span> ` : '';
  div.innerHTML = `${protoHtml}${hostHtml}${esc(label)}${detail ? '  ' + esc(detail) : ''}`;
  terminal.appendChild(div);
  terminal.scrollTop = terminal.scrollHeight;
  if (stOk && level === 'ok') stOk.textContent = okCount;
  if (stFail && level === 'err') stFail.textContent = failCount;
}

function esc(s) {
  if (!s) return '';
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function writeLine(text, cls = '') {
  if (CURRENT_IO && CURRENT_IO.print) { CURRENT_IO.print(text, cls); return; }
  if (!terminal) return;
  const div = document.createElement('div');
  div.className = `line ${cls}`;
  div.textContent = text;
  terminal.appendChild(div);
  terminal.scrollTop = terminal.scrollHeight;
}

function writeHtml(html, cls = '') {
  if (CURRENT_IO && CURRENT_IO.print) {
    // Strip HTML for the console fallback — the plain-text form is enough for
    // banner/help/summary output.
    const plain = html.replace(/<[^>]+>/g, '').replace(/&gt;/g, '>').replace(/&lt;/g, '<').replace(/&amp;/g, '&');
    CURRENT_IO.print(plain, cls);
    return;
  }
  if (!terminal) return;
  const div = document.createElement('div');
  div.className = `line ${cls}`;
  div.innerHTML = html;
  terminal.appendChild(div);
  terminal.scrollTop = terminal.scrollHeight;
}

function showBanner() {
  const banner = [
    '',
    '    ███╗   ██╗██╗  ██╗ ██████╗',
    '    ████╗  ██║╚██╗██╔╝██╔════╝',
    '    ██╔██╗ ██║ ╚███╔╝ ██║     ',
    '    ██║╚██╗██║ ██╔██╗ ██║     ',
    '    ██║ ╚████║██╔╝ ██╗╚██████╗',
    '    ╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝',
    '',
    '  NetExec IWA Edition — Chrome Isolated Web App',
    '  Protocols: SMB · LDAP · WinRM · MSSQL (auth only) · FTP · SSH · RDP · VNC',
    '  Transport: Direct Sockets API (raw TCP from browser)',
    '',
    '  Type "help" for commands, "help <protocol>" for protocol details.',
    '',
  ];
  for (const line of banner) writeLine(line, 'banner');
}

// ---- MODULE DOCS ----
// One line of documentation per module. Only modules listed here appear in
// --help. When you fix a currently-broken module, add its entry back below.
// Keys are `<proto>:<module>`.
const MODULE_DOCS = {
  // ---- SMB ----
  'smb:auth':          'Authentication check (default).',
  'smb:shares':        'Enumerate shares and read/write permissions.',
  'smb:sessions':      'Enumerate active SMB sessions (srvsvc).',
  'smb:logged-on':     'Enumerate logged-on users (wkssvc).',
  'smb:local-groups':  'Enumerate local Administrators / RDP / DCOM members (samr).',
  'smb:reg-sessions':  'Registry sessions (HKU hives → logged-on SIDs).',
  'smb:users':         'Enumerate domain / local users (samr).',
  'smb:groups':        'Enumerate domain / local groups (samr).',
  'smb:rid-brute':     '[MAX]  RID brute-force (default 4000).',
  'smb:pipes':         'Probe accessible named pipes on IPC$.',
  'smb:dialect':       'SMB dialect / signing / encryption / server GUID (no auth).',
  'smb:os-info':       'Dialect + NTLM AV pairs (computer, domain, forest, role).',
  'smb:enum-av':       'Detect installed AV / EDR products.',
  'smb:signing':       'Check SMB signing configuration.',
  'smb:relay':         'Check NTLM relay + WebClient service status.',
  'smb:spooler':       'Check Print Spooler pipe.',
  'smb:petitpotam':    'Check EFSRPC pipe (PetitPotam coercion).',
  'smb:dfscoerce':     'Check DFSNM pipe (DFSCoerce).',
  'smb:shadowcoerce':  'Check FSSAGENT pipe (ShadowCoerce).',
  'smb:webdav':        'Check WebClient service (WebDAV coercion).',
  'smb:coerce':        'Run every coercion pipe check at once.',
  'smb:zerologon':     'CVE-2020-1472 netlogon pipe check.',
  'smb:printnightmare':'CVE-2021-1675 / CVE-2021-34527 PrintNightmare check.',
  'smb:smbghost':      'CVE-2020-0796 SMBGhost check.',
  'smb:ms17-010':      'MS17-010 / EternalBlue SMB1 probe.',
  'smb:epm':           'Enumerate RPC endpoints via port 135 (no auth).',
  'smb:sam':           'Dump SAM hashes via winreg.',
  'smb:lsa':           'Dump LSA secrets + cached DCC2 hashes via winreg.',
  'smb:gpp':           'Extract GPP passwords from SYSVOL.',
  'smb:dcsync':        '[USER]  DCSync via DRSUAPI replication.',
  'smb:exec':          'CMD  Execute command via svcexec.',
  'smb:spider':        '[SHARE]  Spider a share (--pattern REGEX).',
  'smb:files':         '[SHARE]  Scan a share for interesting file names (default C$).',
  'smb:get':           'SHARE/PATH  Download file.',
  'smb:put':           'SHARE/PATH DATA  Upload data.',
  'smb:svc-start':     'NAME  Start a service (svcctl).',
  'smb:svc-stop':      'NAME  Stop a service.',
  'smb:svc-status':    'NAME  Query service state + binPath + start account.',
  'smb:svc-create':    'NAME BIN  Create a service.',
  'smb:svc-delete':    'NAME  Delete a service.',
  'smb:passwd':        'USER PW  Force password change via SAMR.',
  'smb:golden-ticket': 'Forge golden ticket (--krbtgt HASH, --domain-sid SID).',
  'smb:silver-ticket': 'Forge silver ticket (--service-hash, --domain-sid, --spn).',
  'smb:s4u':           'S4U delegation abuse (--impersonate, --target-spn).',
  'smb:dpapi':         'Decrypt DPAPI credential blobs (--master-key).',
  // ---- LDAP ----
  'ldap:auth':         'Authentication check (default).',
  'ldap:signing':      'LDAP signing + channel-binding posture.',
  'ldap:users':        'Enumerate users.',
  'ldap:groups':       'Enumerate groups.',
  'ldap:computers':    'Enumerate computers.',
  'ldap:dcs':          'Enumerate domain controllers.',
  'ldap:spns':         'Enumerate accounts with SPNs.',
  'ldap:kerberoast':   'Find kerberoastable users and request TGS tickets.',
  'ldap:asrep':        'AS-REP roasting for DONT_REQ_PREAUTH accounts.',
  'ldap:pass-pol':     'Dump password policy.',
  'ldap:laps':         'Read LAPS passwords.',
  'ldap:gmsa':         'Find gMSA accounts (msDS-ManagedPassword).',
  'ldap:delegation':   'Enumerate delegation settings.',
  'ldap:trusts':       'Enumerate domain trusts.',
  'ldap:adcs':         'Enumerate ADCS CAs and templates.',
  'ldap:maq':          'Read ms-DS-MachineAccountQuota.',
  'ldap:desc':         'Users with interesting descriptions.',
  'ldap:admins':       'Enumerate privileged group members.',
  'ldap:fgpp':         'Fine-grained password policies.',
  'ldap:subnets':      'AD subnets and sites.',
  'ldap:ous':          'Enumerate OUs.',
  'ldap:gpos':         'Enumerate Group Policy Objects.',
  'ldap:dns':          'Enumerate DNS zones via LDAP.',
  'ldap:dacl':         'Dangerous ACL enumeration.',
  'ldap:nopac':        'CVE-2021-42278/42287 noPac check.',
  'ldap:shadow-creds': 'Shadow Credentials (msDS-KeyCredentialLink) enumeration.',
  'ldap:exchange':     'Enumerate Exchange servers.',
  'ldap:sccm':         'Enumerate SCCM / MECM management points.',
  'ldap:stale-computers': 'Computers inactive > 90 days.',
  'ldap:admin-count':  'Accounts with adminCount=1.',
  'ldap:svc-accounts': 'Service accounts with SPNs.',
  'ldap:trusted-deleg':'Unconstrained delegation computers.',
  'ldap:sidhist':      'Accounts with SID history.',
  'ldap:machine-quota':'Machine account quota.',
  'ldap:dns-zones':    'DNS zones enumeration.',
  'ldap:schema-version':'AD schema + forest functional level.',
  'ldap:large-groups': 'Groups with > 10 members.',
  'ldap:empty-pwd':    'Accounts with no password set.',
  'ldap:pre-win2k':    'Pre-Windows 2000 group members.',
  'ldap:old-passwords':'Accounts with password > 1 year old.',
  'ldap:recycle-bin':  'AD Recycle Bin status + deleted objects.',
  'ldap:enterprise-admins': 'Enterprise + Schema Admins.',
  'ldap:sites':        'AD sites and site links.',
  'ldap:managed-by':   'Groups with managers.',
  'ldap:dns-records':  '[ZONE]  DNS records for zone.',
  'ldap:passnotreqd':  'Accounts with PASSWD_NOTREQD flag.',
  'ldap:never-expires':'Accounts with non-expiring passwords.',
  'ldap:obsolete':     'Legacy / obsolete computers.',
  'ldap:locked':       'Locked-out accounts.',
  'ldap:disabled':     'Disabled accounts.',
  'ldap:func-level':   'Domain / forest functional levels.',
  'ldap:rodc':         'Read-only domain controllers.',
  'ldap:pwd-expired':  'Accounts with expired passwords.',
  'ldap:protected-users': 'Protected Users group members.',
  'ldap:sensitive':    'NOT_DELEGATED accounts.',
  'ldap:recon':        'Quick multi-module domain recon scan.',
  'ldap:search':       'FILTER  Raw LDAP search.',
  'ldap:get-sid':      'SAM  Resolve SID for sAMAccountName.',
  'ldap:add-computer': 'NAME [PW]  Create machine account via MAQ (needs --tls).',
  'ldap:del-computer': 'NAME  Delete machine account.',
  'ldap:rbcd':         'ATK TGT  Write RBCD delegation.',
  'ldap:rbcd-clear':   'TGT  Clear RBCD delegation.',
  'ldap:changepwd':    'USER PW  Change user password (needs --tls).',
  'ldap:disable-user': 'SAM  Disable user account.',
  'ldap:enable-user':  'SAM  Enable user account.',
  'ldap:add-member':   'USER GROUP  Add user to group.',
  'ldap:rm-member':    'USER GROUP  Remove user from group.',
  'ldap:set-spn':      'SAM SPN  Add SPN to account (targeted kerberoast).',
  'ldap:clear-spn':    'SAM SPN  Remove SPN from account.',
  'ldap:set-desc':     'SAM DESC  Set description on AD object.',
  'ldap:set-asrep':    'SAM  Set DONT_REQ_PREAUTH flag (AS-REP roast setup).',
  'ldap:clear-asrep':  'SAM  Clear DONT_REQ_PREAUTH flag.',
  // ---- WinRM ----
  'winrm:auth':        'Authentication check (default).',
  'winrm:exec':        'CMD  Execute command through PowerShell shell.',
  'winrm:ps':          'CMD  Alias for --exec (Shell.run already wraps in PS).',
  'winrm:local-users':  'Local users via Get-LocalUser.',
  'winrm:local-groups': 'Local groups + members via Get-LocalGroup.',
  'winrm:sysinfo':     'systeminfo output.',
  'winrm:ipconfig':    'ipconfig /all output.',
  'winrm:whoami':      'whoami /all output.',
  'winrm:procs':       'Process list (tasklist /V).',
  'winrm:services':    'Running services.',
  'winrm:netstat':     'netstat -ano output.',
  'winrm:av':          'AV / Defender status.',
  'winrm:reg-query':   'KEY  Query registry key.',
  'winrm:env':         'Environment variables.',
  'winrm:users':       'Local users (net user).',
  'winrm:shares':      'Local shares (net share).',
  'winrm:disk':        'Disk info.',
  'winrm:software':    'Installed software.',
  'winrm:tasks':       'Scheduled tasks (non-Microsoft).',
  'winrm:firewall':    'Firewall profile status.',
  'winrm:domain-info': 'Domain / trust info via nltest.',
  'winrm:events':      '[ID]  Security event log query (default 4624).',
  'winrm:privs':       'Token privileges.',
  'winrm:patches':     'Installed hotfixes.',
  'winrm:startup':     'Startup commands.',
  'winrm:drivers':     'Unsigned drivers.',
  'winrm:audit-pol':   'Audit policy settings.',
  'winrm:defender':    'Windows Defender status + exclusions.',
  'winrm:local-admins':'Local Administrators members.',
  'winrm:pipes':       'Named pipes enumeration.',
  'winrm:autorun':     'Autorun registry keys.',
  'winrm:token-privs': 'Token privileges (via whoami /priv).',
  'winrm:lsass':       'LSASS protection status.',
  'winrm:applocker':   'AppLocker configuration.',
  'winrm:bitlocker':   'BitLocker encryption status.',
  'winrm:cred-vault':  'Stored credentials in Windows Credential Vault.',
  'winrm:dotnet':      '.NET and PowerShell versions.',
  'winrm:wifi':        'WiFi profiles and keys.',
  'winrm:wmi':         'CMD  WMI exec.',
  'winrm:wmi-query':   'WQL  WMI query.',
  'winrm:secrets':     'Credential hunting (autologon, unattend, web.config).',
  'winrm:uac':         'UAC configuration check.',
  'winrm:ps-history':  'PowerShell command history.',
  'winrm:get':         'PATH  Download file.',
  'winrm:put':         'PATH DATA  Upload data.',
  // ---- MSSQL ----
  'mssql:auth':        'Credential check (SQL / NTLM / Kerberos).',
  // ---- FTP ----
  'ftp:auth':          'Authentication check.',
  'ftp:anon':          'Test anonymous login.',
  'ftp:banner':        'Grab the FTP banner.',
  'ftp:ls':            '[PATH]  Directory listing (PASV).',
  'ftp:get':           'PATH  Download file.',
  'ftp:put':           'PATH DATA  Upload data.',
  'ftp:brute':         'Brute-force login.',
  'ftp:spider':        'Recursive file listing.',
  'ftp:write-check':   'Test if FTP allows writes.',
  // ---- SSH ----
  'ssh:auth':          'Authentication check.',
  'ssh:banner':        'Grab the SSH banner.',
  'ssh:exec':          'CMD  Execute a command.',
  'ssh:sysinfo':       'System info.',
  'ssh:whoami':        'Whoami output.',
  'ssh:procs':         'Process list.',
  'ssh:netstat':       'Network connections.',
  'ssh:shadow':        'Dump /etc/shadow (needs root).',
  'ssh:keys':          'Enumerate authorized_keys.',
  'ssh:sudo':          'List sudo privileges.',
  'ssh:crontab':       'Enumerate cron jobs.',
  'ssh:suid':          'Find SUID binaries.',
  'ssh:capabilities':  'Find files with capabilities.',
  'ssh:env':           'Environment variables.',
  'ssh:writable':      'Find writable directories.',
  'ssh:interfaces':    'Network interfaces.',
  'ssh:brute':         'Brute-force login.',
  'ssh:recon':         'Quick host recon.',
  'ssh:docker':        'Docker containers / images / volumes.',
  'ssh:users':         'List local users.',
  'ssh:portscan':      'Scan localhost ports via SSH pivot.',
  'ssh:history':       'Shell history analysis.',
  'ssh:configs':       'System config files.',
  'ssh:screens':       'Screen / tmux sessions.',
  'ssh:mounts':        'Mount points + NFS/CIFS shares.',
  'ssh:firewall':      'Firewall rules.',
  'ssh:packages':      'Installed packages + updates.',
  'ssh:secrets':       'Secret files + env vars.',
  // ---- RDP ----
  'rdp:screen':        'Probe RDP endpoint.',
  'rdp:banner':        'RDP banner grab.',
  'rdp:nla':           'Show negotiated RDP security.',
  'rdp:bluekeep':      'CVE-2019-0708 BlueKeep check.',
  // ---- VNC ----
  'vnc:screen':        'Probe VNC endpoint.',
  'vnc:banner':        'VNC banner grab.',
  'vnc:auth':          'Authentication check.',
  'vnc:brute':         'VNC password brute-force.',
};

// Column width for --<flag> in the help output. Long enough for the longest
// flag currently used (--enterprise-admins = 20 chars including dashes).
const FLAG_COL = 22;

function padFlag(flag) {
  return flag.length >= FLAG_COL ? flag + '  ' : flag + ' '.repeat(FLAG_COL - flag.length);
}

// Build the module rows for one protocol. Only modules that are BOTH in
// DISPATCH (routable) AND MODULE_DOCS (documented) show up — hiding a broken
// module is a one-line delete from MODULE_DOCS.
function protoModuleLines(proto) {
  const table = DISPATCH[proto] || {};
  const rows = [];
  for (const mod of Object.keys(table)) {
    const doc = MODULE_DOCS[`${proto}:${mod}`];
    if (!doc) continue;
    rows.push(`    ${padFlag('--' + mod)}${doc}`);
  }
  return rows;
}

const PROTO_HEADER = {
  smb:   'SMB   (port 445 / SMB2)',
  ldap:  'LDAP  (port 389 / 636 with --tls)',
  winrm: 'WinRM (port 5985 / 5986 with --tls)',
  mssql: 'MSSQL (port 1433, --auth only for now)',
  ftp:   'FTP   (port 21)',
  ssh:   'SSH   (port 22)',
  rdp:   'RDP   (port 3389)',
  vnc:   'VNC   (port 5900)',
};

function showHelp(args) {
  const proto = args[0]?.toLowerCase();
  if (proto && DISPATCH[proto]) {
    const rows = protoModuleLines(proto);
    writeLine('');
    writeLine(`  ${PROTO_HEADER[proto] || proto.toUpperCase()}`, 'help');
    for (const r of rows) writeLine(r, 'info');
    writeLine('');
    writeLine(`  Try:  nxc ${proto} <targets> -u USER -p PASS --<module>`, 'info');
    writeLine('');
    return;
  }
  const lines = [
    '',
    '  USAGE',
    '    nxc <protocol> <targets> [options] [--module ...]',
    '',
    '  PROTOCOLS         (run help <protocol> for the module list)',
    '    smb      SMB/CIFS (445)',
    '    ldap     LDAP/LDAPS (389/636)',
    '    winrm    WinRM (5985/5986)',
    '    mssql    MS-SQL (1433) — --auth only for now',
    '    rdp      RDP screening / NLA / BlueKeep (3389)',
    '    ftp      FTP (21)',
    '    ssh      SSH (22)',
    '    vnc      VNC (5900)',
    '',
    '  CREDENTIALS',
    '    -u USER [USER ...]     Username(s) — space-separated for spraying',
    '    -p PASS [PASS ...]     Password(s) — space-separated for spraying',
    '    -H HASH                NT hash (pass-the-hash, LM:NT or NT)',
    '    -d DOMAIN              Domain name',
    '    --local-auth           Auth against target local SAM',
    '    -k, --kerberos         Use Kerberos auth',
    '    --kdc HOST             KDC host (default: target)',
    '    --no-bruteforce        Pair user:pass 1:1 instead of all combinations',
    '',
    '  CONNECTION',
    '    --tls                  Use TLS/SSL (LDAPS, WinRM HTTPS, FTPS, …)',
    '    --port N               Custom port',
    '    --timeout MS           Connection timeout in ms (default 10000)',
    '',
    '  TARGETS',
    '    <targets>              IP / CIDR / IP-range / hostname (space-separated)',
    '    --targets FILE         Load targets from a file (one per line)',
    '    --exclude IP [IP ...]  Exclude targets from the scan',
    '    --jitter MS            Delay between attempts (lockout avoidance)',
    '',
    '  OUTPUT',
    '    --json                 Expand results as JSON inline',
    '    -o, --output           Save JSON as a downloadable file',
    '    --csv                  Save CSV as a downloadable file',
    '    -v / -vv               Verbose / very verbose',
    '',
    '  COMMANDS',
    '    help [protocol]        Full or per-protocol help',
    '    banner                 Show the banner',
    '    clear                  Clear the terminal (standalone UI only)',
    '    stop                   Abort the running scan',
    '',
    '  EXAMPLES',
    '    nxc smb 10.0.0.1 -u admin -p Pass123 -d corp.local',
    '    nxc smb 10.0.0.1 -u admin -H aad3...:31d6... --shares',
    '    nxc smb 10.0.0.0/24 -u admin -p Pass123 --dcsync administrator',
    '    nxc ldap 10.0.0.1 -u admin -p Pass123 -d corp.local --kerberoast',
    '    nxc winrm 10.0.0.1 -u admin -p Pass123 --exec "ipconfig /all"',
    '    nxc mssql 10.0.0.1 -u sa -p Pass123 --auth',
    '',
  ];
  // Per-protocol module sections, driven by MODULE_DOCS ∩ DISPATCH.
  for (const p of ['smb', 'ldap', 'winrm', 'mssql', 'rdp', 'ftp', 'ssh', 'vnc']) {
    const rows = protoModuleLines(p);
    if (!rows.length) continue;
    lines.push('  ' + (PROTO_HEADER[p] || p.toUpperCase()));
    for (const r of rows) lines.push(r);
    lines.push('');
  }
  for (const line of lines) writeLine(line, /^  [A-Z]/.test(line) ? 'help' : 'info');
}

function parseArgs(raw) {
  const tokens = [];
  let i = 0;
  while (i < raw.length) {
    if (raw[i] === ' ') { i++; continue; }
    if (raw[i] === '"') {
      let j = i + 1;
      while (j < raw.length && raw[j] !== '"') j++;
      tokens.push(raw.slice(i + 1, j));
      i = j + 1;
    } else if (raw[i] === "'") {
      let j = i + 1;
      while (j < raw.length && raw[j] !== "'") j++;
      tokens.push(raw.slice(i + 1, j));
      i = j + 1;
    } else {
      let j = i;
      while (j < raw.length && raw[j] !== ' ') j++;
      tokens.push(raw.slice(i, j));
      i = j;
    }
  }
  return tokens;
}

function extractOpts(tokens) {
  const opts = {
    targets: [], users: [], passwords: [], hash: null, domain: '',
    auth: 'ntlm', tls: false, kdc: null, port: null, module: 'auth',
    cmdArgs: '', protocol: '', json: false, noBrute: false, continueOnSuccess: false,
  };
  let i = 0;
  if (tokens[0]?.toLowerCase() === 'nxc') i++;
  if (i < tokens.length && !tokens[i].startsWith('-')) {
    opts.protocol = tokens[i].toLowerCase();
    i++;
  }
  const targetTokens = [];
  while (i < tokens.length && !tokens[i].startsWith('-')) {
    targetTokens.push(tokens[i]);
    i++;
  }
  while (i < tokens.length) {
    const t = tokens[i];
    if (t === '-u' || t === '--user') {
      while (i + 1 < tokens.length && !tokens[i + 1].startsWith('-')) opts.users.push(tokens[++i]);
    }
    else if (t === '-p' || t === '--password') {
      while (i + 1 < tokens.length && !tokens[i + 1].startsWith('-')) opts.passwords.push(tokens[++i]);
    }
    else if (t === '-H' || t === '--hash') { opts.hash = tokens[++i] || ''; }
    else if (t === '-d' || t === '--domain') { opts.domain = tokens[++i] || ''; }
    else if (t === '--local-auth') { opts.localAuth = true; }
    else if (t === '-k' || t === '--kerberos') { opts.auth = 'kerberos'; }
    else if (t === '--kdc') { opts.kdc = tokens[++i] || ''; }
    else if (t === '--krbtgt') { opts.krbtgt = tokens[++i] || ''; }
    else if (t === '--domain-sid') { opts['domain-sid'] = tokens[++i] || ''; }
    else if (t === '--sid') { opts.sid = tokens[++i] || ''; }
    else if (t === '--service-hash') { opts['service-hash'] = tokens[++i] || ''; }
    else if (t === '--target-user') { opts['target-user'] = tokens[++i] || ''; }
    else if (t === '--target-rid') { opts['target-rid'] = tokens[++i] || ''; }
    else if (t === '--master-key') { opts['master-key'] = tokens[++i] || ''; }
    else if (t === '--spn') { opts.spn = tokens[++i] || ''; }
    else if (t === '--impersonate') { opts.impersonate = tokens[++i] || ''; }
    else if (t === '--target-spn') { opts['target-spn'] = tokens[++i] || ''; }
    else if (t === '--service-spn') { opts['service-spn'] = tokens[++i] || ''; }
    else if (t === '--tls' || t === '--ssl') { opts.tls = true; }
    else if (t === '--port') { opts.port = parseInt(tokens[++i]) || null; }
    else if (t === '--json') { opts.json = true; }
    else if (t === '--output' || t === '-o') { opts.output = true; opts.json = true; }
    else if (t === '--csv') { opts.csv = true; opts.json = true; }
    else if (t === '--timeout') { opts.timeout = parseInt(tokens[++i]) || 10000; }
    else if (t === '--targets') { opts.targetsFile = tokens[++i] || ''; }
    else if (t === '--exclude') { if (!opts.excludeTargets) opts.excludeTargets = []; while (i + 1 < tokens.length && !tokens[i + 1].startsWith('-')) opts.excludeTargets.push(tokens[++i]); }
    else if (t === '--openquery') { opts.module = 'openquery'; const srv = tokens[++i] || ''; const sql = tokens[++i] || ''; opts.cmdArgs = `${srv} ${sql}`; }
    else if (t === '--ole') { opts.module = 'ole'; opts.cmdArgs = tokens[++i] || ''; }
    else if (t === '--passwd') { opts.module = 'passwd'; const user = tokens[++i] || ''; const pass = tokens[++i] || ''; opts.cmdArgs = `${user} ${pass}`; }
    else if (t === '--add-computer') { opts.module = 'add-computer'; const name = tokens[++i] || ''; const pw = (i + 1 < tokens.length && !tokens[i + 1].startsWith('-')) ? tokens[++i] : ''; opts.cmdArgs = pw ? `${name} ${pw}` : name; }
    else if (t === '--rbcd') { opts.module = 'rbcd'; const atk = tokens[++i] || ''; const tgt = tokens[++i] || ''; opts.cmdArgs = `${atk} ${tgt}`; }
    else if (t === '--atexec') { opts.module = 'atexec'; opts.cmdArgs = tokens[++i] || ''; }
    else if (t === '--wmi') { opts.module = 'wmi'; opts.cmdArgs = tokens[++i] || ''; }
    else if (t === '--wmi-query') { opts.module = 'wmi-query'; opts.cmdArgs = tokens[++i] || ''; }
    else if (t === '--svc-start') { opts.module = 'svc-start'; opts.cmdArgs = tokens[++i] || ''; }
    else if (t === '--svc-stop') { opts.module = 'svc-stop'; opts.cmdArgs = tokens[++i] || ''; }
    else if (t === '--svc-status') { opts.module = 'svc-status'; opts.cmdArgs = tokens[++i] || ''; }
    else if (t === '--svc-create') { opts.module = 'svc-create'; const n = tokens[++i] || ''; const p = tokens[++i] || ''; opts.cmdArgs = `${n} ${p}`; }
    else if (t === '--svc-delete') { opts.module = 'svc-delete'; opts.cmdArgs = tokens[++i] || ''; }
    else if (t === '--del-computer') { opts.module = 'del-computer'; opts.cmdArgs = tokens[++i] || ''; }
    else if (t === '--changepwd') { opts.module = 'changepwd'; const u = tokens[++i] || ''; const pw = tokens[++i] || ''; opts.cmdArgs = `${u} ${pw}`; }
    else if (t === '--rbcd-clear') { opts.module = 'rbcd-clear'; opts.cmdArgs = tokens[++i] || ''; }
    else if (t === '--disable-user') { opts.module = 'disable-user'; opts.cmdArgs = tokens[++i] || ''; }
    else if (t === '--enable-user') { opts.module = 'enable-user'; opts.cmdArgs = tokens[++i] || ''; }
    else if (t === '--add-member') { opts.module = 'add-member'; const u = tokens[++i] || ''; const g = tokens[++i] || ''; opts.cmdArgs = `${u} ${g}`; }
    else if (t === '--rm-member') { opts.module = 'rm-member'; const u = tokens[++i] || ''; const g = tokens[++i] || ''; opts.cmdArgs = `${u} ${g}`; }
    else if (t === '--set-spn') { opts.module = 'set-spn'; const s = tokens[++i] || ''; const spn = tokens[++i] || ''; opts.cmdArgs = `${s} ${spn}`; }
    else if (t === '--clear-spn') { opts.module = 'clear-spn'; const s = tokens[++i] || ''; const spn = tokens[++i] || ''; opts.cmdArgs = `${s} ${spn}`; }
    else if (t === '--set-desc') { opts.module = 'set-desc'; const s = tokens[++i] || ''; const desc = tokens[++i] || ''; opts.cmdArgs = `${s} ${desc}`; }
    else if (t === '--set-asrep') { opts.module = 'set-asrep'; opts.cmdArgs = tokens[++i] || ''; }
    else if (t === '--clear-asrep') { opts.module = 'clear-asrep'; opts.cmdArgs = tokens[++i] || ''; }
    else if (t === '--ntds') { opts.module = 'ntds'; if (i + 1 < tokens.length && !tokens[i + 1].startsWith('-')) opts.cmdArgs = tokens[++i]; else opts.cmdArgs = ''; }
    else if (t === '--get-sid') { opts.module = 'get-sid'; opts.cmdArgs = tokens[++i] || ''; }
    else if (t === '--reg-query') { opts.module = 'reg-query'; opts.cmdArgs = tokens[++i] || ''; }
    else if (t === '--steal-hash') { opts.module = 'steal-hash'; opts.cmdArgs = tokens[++i] || ''; }
    else if (t === '--events') { opts.module = 'events'; if (i + 1 < tokens.length && /^\d+$/.test(tokens[i + 1])) opts.cmdArgs = tokens[++i]; else opts.cmdArgs = '4624'; }
    else if (t === '--tables') { opts.module = 'tables'; if (i + 1 < tokens.length && !tokens[i + 1].startsWith('-')) opts.cmdArgs = tokens[++i]; else opts.cmdArgs = ''; }
    else if (t === '--columns') { opts.module = 'columns'; opts.cmdArgs = tokens[++i] || ''; }
    else if (t === '--mssql-search') { opts.module = 'mssql-search'; opts.cmdArgs = tokens[++i] || ''; }
    else if (t === '--no-bruteforce') { opts.noBrute = true; }
    else if (t === '--jitter') { opts.jitter = parseInt(tokens[++i]) || 0; }
    else if (t === '-vv') { opts.verbose = 2; }
    else if (t === '-v' || t === '--verbose') { opts.verbose = (opts.verbose || 0) + 1; }
    else if (t === '--continue-on-success') { opts.continueOnSuccess = true; }
    else if (t === '-x' || t === '--exec') { opts.module = 'exec'; opts.cmdArgs = tokens[++i] || ''; }
    else if (t === '-X' || t === '--ps') { opts.module = 'ps'; opts.cmdArgs = tokens[++i] || ''; }
    else if (t === '--query') { opts.module = 'query'; opts.cmdArgs = tokens[++i] || ''; }
    else if (t === '--search') { opts.module = 'search'; opts.cmdArgs = tokens[++i] || ''; }
    else if (t === '--spider') { opts.module = 'spider'; opts.cmdArgs = tokens[++i] || ''; }
    else if (t === '--get') { opts.module = 'get'; opts.cmdArgs = tokens[++i] || ''; }
    else if (t === '--put') { opts.module = 'put'; const path = tokens[++i] || ''; const data = tokens[++i] || ''; opts.cmdArgs = `${path} ${data}`; }
    else if (t === '--db' || t === '--database') { opts.database = tokens[++i] || ''; }
    else if (t === '--pattern') { opts.pattern = tokens[++i] || ''; }
    else if (t === '--depth') { opts.depth = parseInt(tokens[++i]) || 5; }
    else if (t === '--ls') { opts.module = 'ls'; opts.cmdArgs = tokens[i + 1] && !tokens[i + 1].startsWith('-') ? tokens[++i] : ''; }
    else if (t === '--ftp-get') { opts.module = 'get'; opts.cmdArgs = tokens[++i] || ''; }
    else if (t === '--ftp-put') { opts.module = 'put'; const path = tokens[++i] || ''; const data = tokens[++i] || ''; opts.cmdArgs = `${path} ${data}`; }
    else if (t === '--rid-brute') {
      opts.module = 'rid-brute';
      if (i + 1 < tokens.length && /^\d+$/.test(tokens[i + 1])) opts.cmdArgs = tokens[++i];
      else opts.cmdArgs = '4000';
    }
    else if (t === '--dcsync') {
      opts.module = 'dcsync';
      if (i + 1 < tokens.length && !tokens[i + 1].startsWith('-')) opts.cmdArgs = tokens[++i];
      else opts.cmdArgs = '';
    }
    else if (t.startsWith('--')) {
      const mod = t.slice(2);
      if (DISPATCH[opts.protocol]?.[mod] || ['auth','shares','sessions','logged-on','local-groups','users','groups',
        'reg-sessions','computers','dcs','spns','kerberoast','asrep','pass-pol','laps','gmsa','delegation',
        'trusts','adcs','maq','desc','admins','fgpp','subnets','sam','lsa','sysinfo','ipconfig',
        'whoami','procs','services','netstat','av','dbs','privesc','anon','screen',
        'local-users','gpp','dcsync','ls','signing','relay','links',
        'ous','gpos','dns','dacl','openquery','ole','spooler','petitpotam','webdav',
        'dfscoerce','shadowcoerce','coerce','smbghost','zerologon','nopac','printnightmare',
        'shadow-creds','clr','passwd','bluekeep','brute','add-computer','del-computer','rbcd','rbcd-clear','atexec','changepwd','disable-user','enable-user','add-member','rm-member','set-spn','clear-spn',
        'svc-start','svc-stop','svc-status','svc-create','svc-delete',
        'set-desc','set-asrep','clear-asrep','ntds','enum-av','os-info','files','ms17-010','pipes','dialect','nla',
        'shadow','keys','sudo','get-sid','passnotreqd','never-expires','obsolete','locked','disabled',
        'func-level','rodc','pwd-expired','protected-users','sensitive','recon',
        'reg-query','env','disk','software','tasks','steal-hash','impersonate','enum-av','banner',
        'firewall','domain-info','events','privs','patches','recon',
        'crontab','suid','capabilities','writable','interfaces',
        'spider','write-check',
        'docker','portscan','history','configs','screens','mounts','firewall','packages','secrets',
        'exchange','sccm','stale-computers','admin-count','svc-accounts',
        'trusted-deleg','sidhist','machine-quota','dns-zones','schema-version','large-groups',
        'empty-pwd','pre-win2k','old-passwords','recycle-bin','enterprise-admins','sites','managed-by','dns-records',
        'startup','drivers','audit-pol','defender','local-admins','pipes','autorun','token-privs',
        'lsass','applocker','bitlocker','cred-vault','dotnet','wifi',
        'backups','jobs','audit','credentials','triggers','procs','db-size',
        'tables','columns','mssql-search','logins',
        'database',
        'golden-ticket','silver-ticket','s4u','dpapi','wmi','wmi-query','epm',
        'secrets','uac','ps-history'].includes(mod)) {
        opts.module = mod;
      }
    }
    else if (!t.startsWith('-')) { targetTokens.push(t); }
    i++;
  }
  opts.user = opts.users[0] || '';
  opts.password = opts.passwords[0] || '';
  opts.targets = parseTargets(targetTokens.join(' '));
  if (!opts.timeout) opts.timeout = 10000;
  return opts;
}

async function runCommand(line) {
  const trimmed = line.trim();
  if (!trimmed) return;

  writeHtml(`<span style="color:var(--acc);font-weight:700">nxc &gt;</span> ${esc(trimmed)}`, '');

  history.push(trimmed);
  histIdx = history.length;

  return runTokens(parseArgs(trimmed));
}

// Console-integration entry point. `argv` is a token array (the console
// pre-parses the shell-quoted line for us); `io` supplies emit/print
// callbacks; `opts` may carry { ticket } from --ticket resolution.
export async function run(argv, io = {}, opts = {}) {
  CURRENT_IO = io;
  try {
    return await runTokens(argv, opts);
  } finally {
    CURRENT_IO = null;
  }
}

async function runTokens(tokens, extraOpts = {}) {
  const cmd = tokens[0]?.toLowerCase();

  if (cmd === 'help') { showHelp(tokens.slice(1)); return; }
  if (cmd === 'clear') { if (terminal) terminal.innerHTML = ''; return; }
  if (cmd === 'stop') {
    if (abortCtrl) { abortCtrl.abort(); writeLine('Aborted.', 'warn'); }
    else writeLine('Nothing running.', 'info');
    return;
  }
  if (cmd === 'banner') { showBanner(); return; }

  if (cmd !== 'nxc' && !DISPATCH[cmd]) {
    const opts = extractOpts(tokens);
    if (!opts.protocol) {
      writeLine(`Unknown command: ${cmd}. Type "help" for usage.`, 'err');
      return;
    }
  }

  const opts = extractOpts(tokens);
  if (!opts.protocol) {
    writeLine('No protocol specified. Usage: nxc <protocol> <targets> [options]', 'err');
    return;
  }
  if (!DISPATCH[opts.protocol]) {
    writeLine(`Unknown protocol: ${opts.protocol}`, 'err');
    return;
  }
  const handler = DISPATCH[opts.protocol][opts.module];
  if (!handler) {
    writeLine(`Module "${opts.module}" not available for ${opts.protocol}. Try "help ${opts.protocol}"`, 'err');
    return;
  }
  if (!opts.targets.length && !['screen','anon'].includes(opts.module)) {
    writeLine('No targets specified.', 'err');
    return;
  }
  // A --ticket <path> (resolved by console.js into extraOpts.ticket) implies
  // Kerberos and provides the credentials directly — no password/hash needed.
  if (extraOpts.ticket) {
    opts.auth = 'kerberos';
    // If the caller omitted -u, take the client principal from the ticket.
    if (!opts.user) {
      const t = (extraOpts.ticket.tgts && extraOpts.ticket.tgts[0]) || (extraOpts.ticket.serviceTickets && extraOpts.ticket.serviceTickets[0]);
      if (t) {
        opts.user = (t.cname || [])[0] || '';
        if (!opts.domain) opts.domain = (t.crealm || t.realm || '').toLowerCase();
      }
    }
  }
  if (!opts.user && !opts.hash && !extraOpts.ticket && !['screen','anon','signing','smbghost','bluekeep','banner','ms17-010','dialect','nla','golden-ticket','silver-ticket','epm'].includes(opts.module) && opts.protocol !== 'rdp' && opts.protocol !== 'vnc') {
    writeLine('No user specified (-u).', 'err');
    return;
  }

  running = true;
  abortCtrl = new AbortController();
  okCount = 0; failCount = 0;
  if (stOk) stOk.textContent = '0';
  if (stFail) stFail.textContent = '0';
  if (statusEl) { statusEl.textContent = 'running...'; statusEl.className = 'status running'; }

  const users = opts.users.length ? opts.users : [opts.user || ''];
  const passwords = opts.passwords.length ? opts.passwords : [opts.password || ''];
  const credPairs = [];
  if (opts.noBrute) {
    const max = Math.max(users.length, passwords.length);
    for (let i = 0; i < max; i++) {
      credPairs.push({ user: users[i] || users[0], password: passwords[i] || passwords[0], hash: opts.hash, domain: opts.domain, localAuth: !!opts.localAuth });
    }
  } else {
    for (const u of users) {
      for (const p of passwords) {
        credPairs.push({ user: u, password: p, hash: opts.hash, domain: opts.domain, localAuth: !!opts.localAuth });
      }
    }
  }

  const workItems = [];
  for (const host of opts.targets) {
    for (const creds of credPairs) workItems.push({ host, creds });
  }

  if (opts.targetsFile) {
    try {
      const resp = await fetch(opts.targetsFile);
      const text = await resp.text();
      const fileTargets = text.split(/[\r\n]+/).map(l => l.trim()).filter(l => l && !l.startsWith('#'));
      for (const t of fileTargets) {
        for (const ip of parseTargets(t)) opts.targets.push(ip);
      }
    } catch (e) {
      writeLine(`Could not load targets file: ${e.message}`, 'err');
    }
  }

  if (opts.excludeTargets && opts.excludeTargets.length) {
    const excludeSet = new Set();
    for (const ex of opts.excludeTargets) {
      for (const ip of parseTargets(ex)) excludeSet.add(ip);
    }
    opts.targets = opts.targets.filter(t => !excludeSet.has(t));
  }

  const connOpts = { auth: opts.auth, tls: opts.tls, kdc: opts.kdc, port: opts.port, pattern: opts.pattern, depth: opts.depth, database: opts.database, timeout: opts.timeout,
    krbtgt: opts.krbtgt, 'domain-sid': opts['domain-sid'], sid: opts.sid, 'service-hash': opts['service-hash'],
    'target-user': opts['target-user'], 'target-rid': opts['target-rid'], 'master-key': opts['master-key'],
    spn: opts.spn, impersonate: opts.impersonate, 'target-spn': opts['target-spn'], 'service-spn': opts['service-spn'],
    domain: opts.domain, localAuth: !!opts.localAuth,
    ticket: extraOpts.ticket || null,       // pass-the-ticket path — SMB / LDAP handlers pick it up
  };
  const needsArgs = ['exec', 'ps', 'query', 'search', 'spider', 'get', 'put', 'rid-brute', 'dcsync', 'ls', 'openquery', 'ole', 'clr', 'passwd', 'add-computer', 'del-computer', 'rbcd', 'rbcd-clear', 'atexec', 'changepwd', 'disable-user', 'enable-user', 'add-member', 'rm-member', 'set-spn', 'clear-spn', 'svc-start', 'svc-stop', 'svc-status', 'svc-create', 'svc-delete', 'set-desc', 'set-asrep', 'clear-asrep', 'ntds', 'get-sid', 'reg-query', 'steal-hash', 'events', 'tables', 'columns', 'mssql-search', 'dns-records', 'files', 'wmi', 'wmi-query'].includes(opts.module);
  const jsonResults = [];

  if (stTargets) stTargets.textContent = workItems.length;
  const sprayInfo = credPairs.length > 1 ? ` × ${credPairs.length} cred(s) = ${workItems.length} task(s)` : '';
  writeLine(`${opts.protocol} ${opts.targets.length} target(s)${sprayInfo} -u ${users.join(',')} --${opts.module}${opts.cmdArgs ? ' "' + opts.cmdArgs + '"' : ''}`, 'info');

  const verbosity = opts.verbose || 0;
  const baseLog = (level, proto, host, label, detail) => {
    if (level === 'info' && verbosity < 1) return;
    if (level === 'debug' && verbosity < 2) return;
    emit(level, proto, host, label, detail);
  };
  const logWrapper = opts.json
    ? (level, proto, host, label, detail) => {
        baseLog(level, proto, host, label, detail);
        jsonResults.push({ level, proto, host, label, detail: detail || '' });
      }
    : baseLog;

  const concurrency = 8;
  let idx = 0;

  async function worker() {
    while (idx < workItems.length && !abortCtrl.signal.aborted) {
      const { host, creds } = workItems[idx++];
      try {
        if (needsArgs) {
          await handler(host, creds, connOpts, logWrapper, opts.cmdArgs);
        } else {
          await handler(host, creds, connOpts, logWrapper);
        }
      } catch (e) {
        logWrapper('err', opts.protocol, host, 'unhandled', e.message);
      }
      if (opts.jitter && idx < workItems.length) {
        await new Promise(r => setTimeout(r, opts.jitter));
      }
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, workItems.length || 1) }, () => worker());
  await Promise.all(workers);

  writeLine(`Done. ${okCount} success, ${failCount} failed.`, 'info');

  if (opts.json && jsonResults.length) {
    const blob = JSON.stringify(jsonResults, null, 2);
    writeHtml(`<details><summary style="color:var(--acc);cursor:pointer">JSON output (${jsonResults.length} records) — click to expand</summary><pre style="color:var(--dim);font-size:11px;max-height:300px;overflow:auto;white-space:pre-wrap">${esc(blob)}</pre></details>`, '');
  }

  if (opts.output && jsonResults.length) {
    const blob = JSON.stringify(jsonResults, null, 2);
    const file = new Blob([blob], { type: 'application/json' });
    const url = URL.createObjectURL(file);
    const filename = `nxc-${opts.protocol}-${opts.module}-${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
    writeHtml(`<a href="${url}" download="${filename}" style="color:var(--acc)">⬇ Download ${filename} (${jsonResults.length} records)</a>`, 'info');
  }

  if (opts.csv && jsonResults.length) {
    const csvHeader = 'level,proto,host,label,detail';
    const csvRows = jsonResults.map(r => [r.level, r.proto, r.host, `"${(r.label||'').replace(/"/g,'""')}"`, `"${(r.detail||'').replace(/"/g,'""')}"`].join(','));
    const csvText = [csvHeader, ...csvRows].join('\n');
    const csvBlob = new Blob([csvText], { type: 'text/csv' });
    const csvUrl = URL.createObjectURL(csvBlob);
    const csvFilename = `nxc-${opts.protocol}-${opts.module}-${new Date().toISOString().replace(/[:.]/g, '-')}.csv`;
    writeHtml(`<a href="${csvUrl}" download="${csvFilename}" style="color:var(--acc)">⬇ Download ${csvFilename} (CSV, ${jsonResults.length} records)</a>`, 'info');
  }

  if (opts.json && jsonResults.length) {
    const hashModules = ['kerberoast', 'asrep', 'sam', 'lsa', 'dcsync'];
    if (hashModules.includes(opts.module)) {
      const hashLines = jsonResults
        .filter(r => r.level === 'ok' && r.detail && (r.detail.startsWith('$krb5') || r.detail.startsWith('$DCC2') || r.detail.includes(':aad3b435') || r.detail.startsWith('NT:')))
        .map(r => r.detail.startsWith('NT: ') ? r.detail.slice(4) : r.detail);
      if (hashLines.length) {
        const hashText = hashLines.join('\n');
        const hashBlob = new Blob([hashText], { type: 'text/plain' });
        const hashUrl = URL.createObjectURL(hashBlob);
        const hashFilename = `nxc-${opts.module}-hashes-${new Date().toISOString().replace(/[:.]/g, '-')}.txt`;
        writeHtml(`<a href="${hashUrl}" download="${hashFilename}" style="color:var(--acc)">⬇ Download ${hashFilename} (${hashLines.length} hash(es) — hashcat/JtR ready)</a>`, 'info');
      }
    }
  }

  running = false;
  abortCtrl = null;
  if (statusEl) { statusEl.textContent = 'idle'; statusEl.className = 'status'; }
}

// Standalone-page keyboard bindings. Only wire them up when the DOM has both
// the input control and the terminal — the iwa-tools console never has them.
if (input && terminal) {
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      const val = input.value;
      input.value = '';
      if (hintBox) hintBox.classList.remove('visible');
      runCommand(val);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (histIdx > 0) { histIdx--; input.value = history[histIdx]; }
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (histIdx < history.length - 1) { histIdx++; input.value = history[histIdx]; }
      else { histIdx = history.length; input.value = ''; }
    } else if (e.key === 'Tab') {
      e.preventDefault();
      autoComplete();
    } else if (e.key === 'c' && e.ctrlKey) {
      if (abortCtrl) { abortCtrl.abort(); writeLine('^C', 'warn'); }
    } else if (e.key === 'l' && e.ctrlKey) {
      e.preventDefault();
      terminal.innerHTML = '';
    }
  });
}

const COMPLETIONS = {
  protocols: ['smb', 'ldap', 'winrm', 'mssql', 'ftp', 'ssh', 'rdp', 'vnc'],
  flags: ['-u', '-p', '-H', '-d', '-k', '-x', '-X', '--tls', '--kdc', '--port',
    '--json', '--no-bruteforce', '--continue-on-success',
    '--auth', '--shares', '--sessions', '--logged-on', '--local-groups', '--users',
    '--groups', '--reg-sessions', '--rid-brute', '--exec', '--spider', '--get', '--put',
    '--computers', '--dcs', '--spns', '--kerberoast', '--asrep', '--pass-pol',
    '--laps', '--gmsa', '--delegation', '--trusts', '--adcs', '--maq', '--desc',
    '--admins', '--fgpp', '--subnets', '--search',
    '--ps', '--sam', '--lsa', '--sysinfo', '--ipconfig', '--whoami', '--procs',
    '--services', '--netstat', '--av',
    '--query', '--dbs', '--privesc', '--anon', '--screen',
    '--local-users', '--local-groups', '--gpp', '--dcsync',
    '--signing', '--relay', '--links', '--pattern', '--depth', '--output',
    '--ls', '--ftp-get', '--ftp-put', '--ous', '--gpos', '--dns',
    '--openquery', '--csv', '--timeout', '--targets',
    '--spooler', '--petitpotam', '--webdav', '--jitter', '--dacl', '--exclude',
    '--dfscoerce', '--shadowcoerce', '--coerce', '--smbghost', '--ole',
    '--zerologon', '--nopac', '--printnightmare', '--shadow-creds', '--clr',
    '--add-computer', '--del-computer', '--rbcd', '--rbcd-clear', '--passwd',
    '--bluekeep', '--brute', '--atexec', '--changepwd', '--disable-user', '--enable-user',
    '--add-member', '--rm-member', '--set-spn', '--clear-spn',
    '--svc-start', '--svc-stop', '--svc-status', '--svc-create', '--svc-delete',
    '--set-desc', '--set-asrep', '--clear-asrep', '--ntds',
    '--shadow', '--keys', '--sudo',
    '--get-sid', '--passnotreqd', '--never-expires', '--obsolete', '--locked', '--disabled',
    '--reg-query', '--env', '--disk', '--software', '--tasks',
    '--steal-hash', '--impersonate', '--ntds', '--enum-av', '--os-info', '--files', '--ms17-010', '--pipes', '--dialect', '--nla',
    '--banner', '--func-level', '--rodc', '--pwd-expired', '--protected-users', '--sensitive', '--recon',
    '--firewall', '--domain-info', '--events', '--privs', '--patches',
    '--crontab', '--suid', '--capabilities', '--writable', '--interfaces',
    '--spider', '--write-check',
    '--docker', '--portscan', '--history', '--configs', '--screens', '--mounts', '--firewall', '--packages', '--secrets',
    '--exchange', '--sccm', '--stale-computers', '--admin-count', '--svc-accounts',
    '--trusted-deleg', '--sidhist', '--machine-quota', '--dns-zones', '--schema-version', '--large-groups',
    '--empty-pwd', '--pre-win2k', '--old-passwords', '--recycle-bin', '--enterprise-admins', '--sites', '--managed-by', '--dns-records',
    '--startup', '--drivers', '--audit-pol', '--defender', '--local-admins', '--pipes', '--autorun', '--token-privs',
    '--lsass', '--applocker', '--bitlocker', '--cred-vault', '--dotnet', '--wifi',
    '--backups', '--jobs', '--audit', '--credentials', '--triggers', '--procs', '--db-size',
    '--tables', '--columns', '--mssql-search', '--logins',
    '--golden-ticket', '--silver-ticket', '--s4u', '--dpapi',
    '--krbtgt', '--domain-sid', '--sid', '--service-hash', '--target-user', '--target-rid',
    '--master-key', '--spn', '--impersonate', '--target-spn', '--service-spn'],
};

function autoComplete() {
  if (!input || !hintBox) return;
  const val = input.value;
  const tokens = val.split(/\s+/);
  const last = tokens[tokens.length - 1]?.toLowerCase() || '';
  let candidates = [];

  if (tokens.length <= 1) {
    candidates = ['nxc', 'help', 'clear', 'stop'].filter(c => c.startsWith(last));
  } else if (tokens.length === 2 && (tokens[0] === 'nxc' || tokens[0] === 'help')) {
    candidates = COMPLETIONS.protocols.filter(c => c.startsWith(last));
  } else if (last.startsWith('-')) {
    candidates = COMPLETIONS.flags.filter(c => c.startsWith(last));
  }

  if (candidates.length === 1) {
    tokens[tokens.length - 1] = candidates[0];
    input.value = tokens.join(' ') + ' ';
    hintBox.classList.remove('visible');
  } else if (candidates.length > 1) {
    hintBox.innerHTML = '';
    for (const c of candidates) {
      const div = document.createElement('div');
      div.className = 'hint-item';
      div.textContent = c;
      div.onclick = () => {
        tokens[tokens.length - 1] = c;
        input.value = tokens.join(' ') + ' ';
        hintBox.classList.remove('visible');
        input.focus();
      };
      hintBox.appendChild(div);
    }
    hintBox.classList.add('visible');
  }
}

if (input && hintBox) {
  input.addEventListener('input', () => { hintBox.classList.remove('visible'); });
  document.addEventListener('click', (e) => { if (!hintBox.contains(e.target)) hintBox.classList.remove('visible'); });
}

if (terminal) showBanner();
if (input) input.focus();
