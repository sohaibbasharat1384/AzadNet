'use strict';
const fs=require('node:fs/promises');
const path=require('node:path');
const net=require('node:net');
const dns=require('node:dns/promises');
const crypto=require('node:crypto');
const {spawn}=require('node:child_process');
const {NativeIKEv2}=require('./native-ikev2.cjs');
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const protocolOf=p=>p?.type==='ikev2'?'ikev2':p?.type==='wireguard'?'wireguard':p?.type==='openvpn'?(p['windscribe-mode']||p.proto):null;
const isExternal=p=>['ikev2','stealth','wstunnel'].includes(protocolOf(p));
function clean(p){const value=structuredClone(p);for(const key of ['windscribe-mode','outer-server','outer-port','outer-sni','outer-padding'])delete value[key];return value;}
async function freePort(){return new Promise((resolve,reject)=>{const s=net.createServer();s.once('error',reject);s.listen(0,'127.0.0.1',()=>{const port=s.address().port;s.close(()=>resolve(port));});});}
async function listening(port){return new Promise(resolve=>{const socket=net.connect({host:'127.0.0.1',port});socket.setTimeout(200,()=>socket.destroy());socket.once('connect',()=>{socket.destroy();resolve(true);});socket.once('error',()=>resolve(false));socket.once('close',()=>resolve(false));});}
class WindscribeRuntime{
  constructor({dataDir,corePath,platform=process.platform,nativeIKE,spawnProcess=spawn,lookup=dns.lookup,log=()=>{},onFailure=()=>{}}={}){
    this.platform=platform;this.native=nativeIKE||new NativeIKEv2({dataDir,platform});this.spawn=spawnProcess;this.lookup=lookup;this.log=log;this.onFailure=onFailure;this.child=null;this.failure=null;
    const folder=platform==='win32'?'windows':'linux';this.helper=path.join(path.dirname(corePath),'..','windscribe',folder,platform==='win32'?'windscribe-tunnel.exe':'windscribe-tunnel');
  }
  async verifyHelper(){
    const identity=JSON.parse(await fs.readFile(path.join(path.dirname(this.helper),'build.json'),'utf8'));
    const digest=crypto.createHash('sha256').update(await fs.readFile(this.helper)).digest('hex');
    if(identity.sourceCommit!=='e6c325eed099e746ee98f80de7b827e942416d20'||identity.tlsCompatibilityTestsPassed!==true||identity.platform!==(this.platform==='win32'?'windows':'linux')||identity.sha256!==digest)throw new Error('Windscribe tunnel helper identity mismatch');
  }
  async availability(){
    let tunnel=false;try{await this.verifyHelper();tunnel=true;}catch{}
    return {wireguard:true,udp:true,tcp:true,stealth:tunnel,wstunnel:tunnel,ikev2:await this.native.available(),platform:this.platform};
  }
  async recover(){await this.native.stop();}
  async prepare(selected,proxies,{testOnly=false}={}){
    const normal=proxies.filter(p=>!isExternal(p)).map(clean);
    if(testOnly||!isExternal(selected))return {proxies:normal,nativeVpn:false,routeExcludes:[]};
    if(selected.type==='ikev2'){
      await this.native.start(selected);
      return {proxies:[...normal,{name:selected.name,type:'direct'}],nativeVpn:true,routeExcludes:[]};
    }
    const host=selected['outer-server']||selected.server,port=selected['outer-port']||443;
    if(typeof host!=='string'||/[\s/?#@%]/.test(host)||!host||!Number.isInteger(port)||port<1||port>65535)throw new Error('Invalid Windscribe outer endpoint');
    const sni=selected['outer-sni']||(!net.isIP(host)?host:'');
    if(typeof sni!=='string'||/[\s/:?#@%\x00-\x1f]/.test(sni))throw new Error('Invalid Windscribe TLS server name');
    await this.verifyHelper();
    const addresses=net.isIP(host)?[{address:host,family:net.isIP(host)}]:await this.lookup(host,{all:true});
    const peer=addresses.find(x=>x.family===4)||addresses.find(x=>x.family===6);
    if(!peer||!net.isIP(peer.address)||peer.address.includes('%'))throw new Error('Windscribe outer endpoint did not resolve');
    const localPort=await freePort(),mode=protocolOf(selected);
    const address=peer.family===6?`[${peer.address}]`:peer.address;
    const remote=mode==='stealth'?`https://${address}:${port}`:`wss://${address}:${port}/tcp/127.0.0.1/1194`;
    const args=['--listenAddress',`127.0.0.1:${localPort}`,'--remoteAddress',remote,'--tunnelType',mode==='stealth'?'2':'1','--logFilePath',''];
    if(sni)args.push('--tlsServerName',sni);
    if(mode==='stealth'&&selected['outer-padding']===true)args.push('--extraTlsPadding');
    this.failure=null;
    const child=this.spawn(this.helper,args,{windowsHide:true,shell:false,stdio:['ignore','pipe','pipe']});this.child=child;
    child.once('error',()=>{this.failure=new Error('Windscribe tunnel helper could not start');});
    child.once('exit',(code,signal)=>{if(this.child===child){this.child=null;this.failure=new Error(`Windscribe tunnel helper exited (${signal||code})`);this.onFailure(this.failure);}});
    for(const stream of [child.stdout,child.stderr]){let pending='';stream?.on('data',data=>{pending+=data.toString();const lines=pending.split(/\r?\n/);pending=lines.pop().slice(-2000);for(const line of lines)this.log(line);});}
    let ready=false;
    for(let i=0;i<50;i++){if(this.failure)throw this.failure;if(await listening(localPort)){ready=true;break;}await sleep(100);}
    if(!ready)throw new Error('Windscribe tunnel helper did not become ready');
    const outbound={...clean(selected),server:'127.0.0.1',port:localPort,proto:'tcp'};
    return {proxies:[...normal,outbound],nativeVpn:false,routeExcludes:[`${peer.address}/${peer.family===4?32:128}`]};
  }
  async stop(){
    const child=this.child;this.child=null;this.failure=null;
    if(child)await new Promise(resolve=>{let done=false;const finish=()=>{if(done)return;done=true;clearTimeout(timer);resolve();};child.once('exit',finish);const timer=setTimeout(()=>{try{child.kill('SIGKILL');}catch{}finish();},2000);try{child.kill();}catch{finish();}if(child.exitCode!==null&&child.exitCode!==undefined)finish();});
    await this.native.stop();
  }
}
module.exports={WindscribeRuntime,protocolOf,isExternal};
