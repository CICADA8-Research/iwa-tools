
import net from 'node:net'; import { webcrypto } from 'node:crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;
globalThis.TCPSocket=class{constructor(host,port){const ch=[];let w=null,en=false,er=null;const s=net.connect(port,host);this._s=s;s.on('data',d=>{const u=Uint8Array.from(d);if(w){const x=w;w=null;x.resolve({value:u,done:false});}else ch.push(u);});s.on('end',()=>{en=true;if(w){const x=w;w=null;x.resolve({done:true});}});s.on('error',e=>{er=e;if(w){const x=w;w=null;x.reject(e);}});const rd={read(){if(ch.length)return Promise.resolve({value:ch.shift(),done:false});if(er)return Promise.reject(er);if(en)return Promise.resolve({done:true});return new Promise((re,rj)=>{w={resolve:re,reject:rj};});},releaseLock(){}};const wr={write:b=>new Promise((re,rj)=>s.write(Buffer.from(b),e=>(e?rj(e):re()))),releaseLock(){}};this.opened=new Promise((re,rj)=>{s.once('connect',()=>re({remoteAddress:s.remoteAddress,remotePort:s.remotePort,readable:{getReader:()=>rd},writable:{getWriter:()=>wr}}));s.once('error',rj);});}async close(){try{this._s.destroy();}catch{}}};
const { IwaConsole } = await import('../src/console.js');
const io={print:(x,c)=>console.log((c?`[${c}] `:'  ')+x),setPrompt(){},clear(){},download(){}};
const con=new IwaConsole(io);
await con.submit('nxc smb 100.100.10.100 -u administrator -p P@ssw0rd -x whoami');
process.exit(0);
