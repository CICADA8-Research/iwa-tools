// WS-Management (MS-WSMV) Windows Remote Shell SOAP messages and response
// extractors. These are plain SOAP 1.2 XML (the binary NBFX encoding is ADWS-
// only); the WinRM client seals the UTF-8 bytes for transport. Message shapes
// mirror pywinrm/Evil-WinRM.

const NS =
  'xmlns:s="http://www.w3.org/2003/05/soap-envelope" ' +
  'xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" ' +
  'xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" ' +
  'xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd" ' +
  'xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"';

const SHELL_URI = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd';
const A = {
  Create: 'http://schemas.xmlsoap.org/ws/2004/09/transfer/Create',
  Delete: 'http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete',
  Command: 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command',
  Receive: 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive',
  Signal: 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal',
};

export function uuid() {
  if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID();
  const b = globalThis.crypto.getRandomValues(new Uint8Array(16));
  b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80;
  const h = [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

export function escapeXml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function header(to, action, { shellId, options } = {}) {
  let opt = '';
  if (options) {
    opt = '<w:OptionSet>' + options.map((o) => `<w:Option Name="${o.name}">${escapeXml(o.value)}</w:Option>`).join('') + '</w:OptionSet>';
  }
  const sel = shellId ? `<w:SelectorSet><w:Selector Name="ShellId">${escapeXml(shellId)}</w:Selector></w:SelectorSet>` : '';
  return '<s:Header>' +
    `<a:To>${escapeXml(to)}</a:To>` +
    `<w:ResourceURI s:mustUnderstand="true">${SHELL_URI}</w:ResourceURI>` +
    '<a:ReplyTo><a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>' +
    '<w:MaxEnvelopeSize s:mustUnderstand="true">153600</w:MaxEnvelopeSize>' +
    `<a:MessageID>uuid:${uuid()}</a:MessageID>` +
    '<w:Locale xml:lang="en-US" s:mustUnderstand="false"/>' +
    '<p:DataLocale xml:lang="en-US" s:mustUnderstand="false"/>' +
    '<w:OperationTimeout>PT30S</w:OperationTimeout>' +
    `<a:Action s:mustUnderstand="true">${action}</a:Action>` +
    sel + opt +
    '</s:Header>';
}

const envelope = (to, action, opts, body) =>
  `<s:Envelope ${NS}>${header(to, action, opts)}<s:Body>${body}</s:Body></s:Envelope>`;

export function createShell(to) {
  return envelope(to, A.Create, { options: [
    { name: 'WINRS_NOPROFILE', value: 'FALSE' },
    { name: 'WINRS_CODEPAGE', value: '437' },
  ] }, '<rsp:Shell><rsp:InputStreams>stdin</rsp:InputStreams><rsp:OutputStreams>stdout stderr</rsp:OutputStreams></rsp:Shell>');
}

export function runCommand(to, shellId, command) {
  return envelope(to, A.Command, { shellId, options: [
    { name: 'WINRS_CONSOLEMODE_STDIN', value: 'TRUE' },
    { name: 'WINRS_SKIP_CMD_SHELL', value: 'FALSE' },
  ] }, `<rsp:CommandLine><rsp:Command>${escapeXml(command)}</rsp:Command></rsp:CommandLine>`);
}

export function receive(to, shellId, commandId) {
  return envelope(to, A.Receive, { shellId },
    `<rsp:Receive><rsp:DesiredStream CommandId="${escapeXml(commandId)}">stdout stderr</rsp:DesiredStream></rsp:Receive>`);
}

export function signal(to, shellId, commandId) {
  return envelope(to, A.Signal, { shellId },
    `<rsp:Signal CommandId="${escapeXml(commandId)}"><rsp:Code>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/terminate</rsp:Code></rsp:Signal>`);
}

export function deleteShell(to, shellId) {
  return envelope(to, A.Delete, { shellId }, '');
}

// ---- response extractors (regex over the well-defined WSMV responses) ------
const b64decode = (s) => (typeof atob === 'function'
  ? Uint8Array.from(atob(s), (c) => c.charCodeAt(0))
  : Uint8Array.from(Buffer.from(s, 'base64')));

export function getShellId(xml) {
  let m = /<(?:\w+:)?Selector[^>]*Name="ShellId"[^>]*>([^<]+)</.exec(xml);
  if (m) return m[1];
  m = /<(?:rsp:)?ShellId>([^<]+)</.exec(xml);
  return m ? m[1] : null;
}
export function getCommandId(xml) {
  const m = /<(?:rsp:)?CommandId>([^<]+)</.exec(xml);
  return m ? m[1] : null;
}

// Returns { stdout: Uint8Array, stderr: Uint8Array, done: bool, exitCode: number|null }.
export function parseReceiveResponse(xml) {
  const out = [], err = [];
  const re = /<(?:rsp:)?Stream\b([^>]*)>([\s\S]*?)<\/(?:rsp:)?Stream>/g;
  let m;
  while ((m = re.exec(xml))) {
    const attrs = m[1], text = m[2].trim();
    if (!text) continue;
    const name = /Name="([^"]+)"/.exec(attrs);
    const bytes = b64decode(text);
    if (name && name[1] === 'stderr') err.push(bytes); else out.push(bytes);
  }
  const state = /<(?:rsp:)?CommandState[^>]*State="([^"]+)"/.exec(xml);
  const done = state ? /\/Done$/.test(state[1]) : false;
  const ec = /<(?:rsp:)?ExitCode>(-?\d+)</.exec(xml);
  return { stdout: concatBytes(out), stderr: concatBytes(err), done, exitCode: ec ? Number(ec[1]) : null };
}

export function getFault(xml) {
  if (!/<(?:\w+:)?Fault\b/.test(xml)) return null;
  const reason = /<(?:\w+:)?(?:Text|Reason)[^>]*>([\s\S]*?)<\/(?:\w+:)?(?:Text|Reason)>/.exec(xml);
  const code = /<(?:\w+:)?WSManFault[^>]*Code="(\d+)"/.exec(xml);
  return { message: reason ? reason[1].trim() : 'SOAP fault', code: code ? Number(code[1]) : null };
}

function concatBytes(list) {
  let t = 0; for (const a of list) t += a.length;
  const o = new Uint8Array(t); let off = 0;
  for (const a of list) { o.set(a, off); off += a.length; }
  return o;
}
