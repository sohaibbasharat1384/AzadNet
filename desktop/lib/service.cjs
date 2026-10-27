'use strict';
const fs=require('node:fs/promises');
const path=require('node:path');
const crypto=require('node:crypto');
const net=require('node:net');
const https=require('node:https');
const {spawn}=require('node:child_process');
const {stringify}=require('yaml');
const {parseSubscription,MAX_TEXT,validateProxy}=require('./subscriptions.cjs');
const {DEFAULT_SETTINGS,validateSettings,generateConfig}=require('./config.cjs');
const {Controller}=require('./controller.cjs');
const {downloadSpeed}=require('./diagnostics.cjs');
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
function fingerprint(proxy){const order=v=>Array.isArray(v)?v.map(order):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).filter(k=>k!=='name').sort().map(k=>[k,order(v[k])])):v;return crypto.createHash('sha256').update(JSON.stringify(order(proxy))).digest('hex');}
async function atomicJson(file,value){const tmp=`${file}.${crypto.randomBytes(5).toString('hex')}.tmp`;await fs.writeFile(tmp,JSON.stringify(value,null,2),{mode:0o600});try{await fs.rename(tmp,file);}catch(e){await fs.rm(tmp,{force:true});throw e;}}
function fetchSubscription(url,redirects=0){
  return new Promise((resolve,reject)=>{
    let u;try{u=new URL(url);}catch{reject(new Error('Invalid subscription URL'));return;}
    if(u.protocol!=='https:'||u.username||u.password){reject(new Error('Subscriptions require HTTPS URLs without embedded credentials'));return;}
    if(redirects>3){reject(new Error('Too many subscription redirects'));return;}
    const req=https.get(u,{headers:{'User-Agent':'AzadNet/1.0 Mihomo','Accept':'text/plain,application/yaml,application/json'}},res=>{
      if([301,302,303,307,308].includes(res.statusCode)){
        res.resume();clearTimeout(timer);let target;try{target=new URL(res.headers.location,u);}catch{reject(new Error('Invalid subscription redirect'));return;}
        fetchSubscription(target.toString(),redirects+1).then(resolve,reject);return;
      }
      if(res.statusCode!==200){res.resume();clearTimeout(timer);reject(new Error(`Subscription returned HTTP ${res.statusCode}`));return;}
      if(Number(res.headers['content-length'])>MAX_TEXT){res.destroy();clearTimeout(timer);reject(new Error('Subscription exceeds 8 MiB'));return;}
      let bytes=0,chunks=[];res.on('data',b=>{bytes+=b.length;if(bytes>MAX_TEXT){res.destroy(new Error('Subscription exceeds 8 MiB'));return;}chunks.push(b);});
      res.on('error',e=>{clearTimeout(timer);reject(e);});res.on('end',()=>{clearTimeout(timer);resolve(Buffer.concat(chunks).toString('utf8'));});
    });
    const timer=setTimeout(()=>req.destroy(new Error('Subscription download timed out')),20000);req.on('error',e=>{clearTimeout(timer);reject(e);});
  });
}
async function checkPort(port){return new Promise((resolve,reject)=>{const s=net.createServer();s.unref();s.once('error',()=>reject(new Error(`Local port ${port} is already in use`)));s.listen(port,'127.0.0.1',()=>s.close(resolve));});}
class Service{
  constructor({dataDir,corePath,emit=()=>{},spawnProcess=spawn,fetchText=fetchSubscription,fragmentsSupported=false}={}){
    if(!dataDir)throw new Error('dataDir is required');
    this.dataDir=dataDir;this.file=path.join(dataDir,'state.json');this.corePath=corePath||process.env.AZADNET_CORE_PATH||path.join(process.resourcesPath||path.join(__dirname,'..','..','resources'),'core',process.platform==='win32'?'mihomo.exe':'mihomo');this.emit=emit;this.spawnProcess=spawnProcess;this.fetchText=fetchText;this.fragmentsSupported=fragmentsSupported===true;this.shuttingDown=false;this.startPromise=null;this.validationProcess=null;
    this.settings={...structuredClone(DEFAULT_SETTINGS),lanPassword:crypto.randomBytes(12).toString('base64url')};this.subscriptions=[];this.selectedServer=null;this.status='disconnected';this.coreVersion=null;this.error=null;this.logs=[];this.process=null;this.controller=null;this.secret='';this.delays=new Map();this.busy=false;this.testing=false;this.speedTesting=false;this.speedTestAbort=null;
  }
  async init(){
    await fs.mkdir(this.dataDir,{recursive:true,mode:0o700});
    try{
      const stat=await fs.stat(this.file);if(stat.size>16*1024*1024)throw new Error('Saved state exceeds size limit');
      const saved=JSON.parse(await fs.readFile(this.file,'utf8'));this.settings=validateSettings(saved.settings||{},this.settings);if(!this.settings.lanPassword)this.settings.lanPassword=crypto.randomBytes(12).toString('base64url');
      if(!Array.isArray(saved.subscriptions)||saved.subscriptions.length>100)throw new Error('Invalid saved subscriptions');
      this.subscriptions=saved.subscriptions.map(s=>{
        if(typeof s.id!=='string'||typeof s.name!=='string'||!Array.isArray(s.proxies)||s.proxies.length>10000)throw new Error('Invalid saved subscription');
        if(s.url){const u=new URL(s.url);if(u.protocol!=='https:'||u.username||u.password)throw new Error('Invalid saved subscription URL');}
        return {...s,proxies:s.proxies.map((p,i)=>validateProxy(p,i+1))};
      });
      this.selectedServer=typeof saved.selectedServer==='string'?saved.selectedServer:null;
    }catch(e){if(e.code!=='ENOENT'){this.log('Saved settings could not be loaded; defaults restored.');this.error='Saved settings could not be loaded';this.settings={...structuredClone(DEFAULT_SETTINGS),lanPassword:crypto.randomBytes(12).toString('base64url')};this.subscriptions=[];}}
    this.publish();return this.getState();
  }
  proxyList(){return this.subscriptions.flatMap(s=>s.proxies);}
  getState(){return {settings:structuredClone(this.settings),subscriptions:this.subscriptions.map(s=>({id:s.id,name:s.name,url:s.url?new URL(s.url).origin:undefined,count:s.proxies.length,updatedAt:s.updatedAt})),servers:this.subscriptions.flatMap(s=>s.proxies.map(p=>({name:p.name,type:p.type,server:p.server,port:p.port,subscriptionId:s.id,delay:this.delays.get(p.name)??null}))),selectedServer:this.selectedServer,status:this.status,coreVersion:this.coreVersion,error:this.error,testing:this.testing,speedTesting:this.speedTesting,capabilities:{fragmentsSupported:this.fragmentsSupported}};}
  publish(){this.emit('state',this.getState());}
  log(line){
    let text=String(line).replace(/\u001b\[[0-9;]*m/g,'').replace(/[\x00-\x08\x0b-\x1f]/g,'').trim().slice(0,2000);if(!text)return;
    if(this.secret)text=text.split(this.secret).join('[redacted]');
    if(this.settings.lanPassword?.length>=5)text=text.split(this.settings.lanPassword).join('[redacted]');
    for(const p of this.proxyList())for(const key of ['password','uuid','private-key'])if(typeof p[key]==='string'&&p[key].length>5)text=text.split(p[key]).join('[redacted]');
    text=text.replace(/(?:vmess|vless|trojan|ss|hy2|hysteria2|tuic):\/\/\S+/gi,'[proxy URI redacted]').replace(/(password|secret|token|auth(?:orization)?|private-key)\s*[:=]\s*[^\s,]+/gi,'$1=[redacted]');
    const entry={time:new Date().toISOString(),message:text};this.logs.push(entry);if(this.logs.length>500)this.logs.splice(0,this.logs.length-500);this.emit('log',entry);
  }
  getLogs(){return this.logs.map(x=>({...x}));}
  async persist(){await atomicJson(this.file,{version:1,settings:this.settings,subscriptions:this.subscriptions,selectedServer:this.selectedServer});}
  requireIdle(){if(this.busy||this.testing||this.status!=='disconnected')throw new Error('Disconnect before changing configuration');}
  async saveSettings(patch){this.requireIdle();this.busy=true;try{this.settings=validateSettings(patch,this.settings);await this.persist();this.publish();return this.getState();}finally{this.busy=false;}}
  async storeImport(text,name,url,existing){
    if(!existing&&this.subscriptions.length>=100)throw new Error('At most 100 subscriptions are supported');
    if(typeof name!=='string'||!name.trim()||name.length>180)throw new Error('Invalid subscription name');
    const {proxies,warnings}=parseSubscription(text),others=this.subscriptions.filter(s=>s.id!==existing?.id).flatMap(s=>s.proxies),used=new Set(['AZADNET','DIRECT','REJECT','GLOBAL',...others.map(p=>p.name)]),renames=new Map();
    if(others.length+proxies.length>20000)throw new Error('At most 20000 servers are supported');
    const previous=new Map((existing?.proxies||[]).map(p=>[fingerprint(p),p.name]));
    for(const p of proxies){const original=p.name,preferred=previous.get(fingerprint(p))||original;let unique=preferred;for(let n=2;used.has(unique);n++)unique=`${preferred} (${n})`;p.name=unique;used.add(unique);if(!renames.has(original))renames.set(original,unique);}
    for(const p of proxies)if(p['dialer-proxy']&&renames.has(p['dialer-proxy']))p['dialer-proxy']=renames.get(p['dialer-proxy']);
    const s={id:existing?.id||crypto.randomUUID(),name:name.trim(),proxies,updatedAt:new Date().toISOString(),...(url?{url}:{})};
    if(existing)this.subscriptions[this.subscriptions.findIndex(p=>p.id===existing.id)]=s;else this.subscriptions.push(s);
    if(!this.proxyList().some(p=>p.name===this.selectedServer))this.selectedServer=proxies[0].name;
    await this.persist();this.publish();return {id:s.id,count:proxies.length,warnings};
  }
  async importText(text,name='Imported subscription'){
    this.requireIdle();this.busy=true;try{return await this.storeImport(text,name);}finally{this.busy=false;}
  }
  async importUrl(url,name='Subscription'){
    this.requireIdle();if(typeof url!=='string'||url.length>4096)throw new Error('Invalid subscription URL');
    this.busy=true;try{this.log('Downloading subscription over HTTPS…');const text=await this.fetchText(url);return await this.storeImport(text,name,url);}finally{this.busy=false;}
  }
  async refreshSubscription(id){
    this.requireIdle();const s=this.subscriptions.find(s=>s.id===id);if(!s)throw new Error('Subscription not found');if(!s.url)throw new Error('This subscription was imported from text and has no refresh URL');
    this.busy=true;try{this.log('Refreshing subscription over HTTPS…');const text=await this.fetchText(s.url);return await this.storeImport(text,s.name,s.url,s);}finally{this.busy=false;}
  }
  async removeSubscription(id){this.requireIdle();if(typeof id!=='string')throw new Error('Invalid subscription id');const index=this.subscriptions.findIndex(s=>s.id===id);if(index<0)throw new Error('Subscription not found');this.subscriptions.splice(index,1);if(!this.proxyList().some(p=>p.name===this.selectedServer))this.selectedServer=this.proxyList()[0]?.name||null;this.busy=true;try{await this.persist();this.publish();return this.getState();}finally{this.busy=false;}}
  async selectServer(name){
    if(this.speedTesting)throw new Error('Wait for the speed test to finish before changing servers');
    if(this.busy)throw new Error('Connection operation in progress');if(!this.proxyList().some(p=>p.name===name))throw new Error('Server not found');
    if(this.status==='connected')await this.controller.select(name,this.settings.mode==='global'?'GLOBAL':'AZADNET');
    this.selectedServer=name;await this.persist();this.publish();return this.getState();
  }
  spawnCore(args){return this.spawnProcess(this.corePath,args,{cwd:this.dataDir,windowsHide:true,stdio:['ignore','pipe','pipe'],shell:false});}
  capture(child){for(const stream of [child.stdout,child.stderr]){if(!stream)continue;let pending='';stream.on('data',chunk=>{pending+=chunk.toString();const lines=pending.split(/\r?\n/);pending=lines.pop().slice(-4000);for(const line of lines)this.log(line);});stream.on('end',()=>{if(pending)this.log(pending);});}}
  async testConfig(file){return new Promise((resolve,reject)=>{
    const child=this.spawnCore(['-t','-d',this.dataDir,'-f',file]);this.validationProcess=child;this.capture(child);let settled=false;
    const done=(err)=>{if(settled)return;settled=true;clearTimeout(timer);if(this.validationProcess===child)this.validationProcess=null;err?reject(err):resolve();};
    const timer=setTimeout(()=>{child.kill();done(new Error('Core configuration validation timed out'));},15000);
    child.once('error',()=>done(new Error('Could not launch Mihomo core')));child.once('exit',(code,signal)=>done(code===0?null:new Error(`Mihomo rejected configuration (${signal||code}); see logs`)));
  });}
  async start(){
    if(this.shuttingDown)throw new Error('Application is shutting down');
    if(this.startPromise)throw new Error('Connection operation in progress');
    this.startPromise=this.runStart();try{return await this.startPromise;}finally{this.startPromise=null;}
  }
  async runStart(){
    if(this.busy)throw new Error('Connection operation in progress');if(this.status==='connected')return this.getState();if(!this.proxyList().length)throw new Error('Import a subscription or server first');
    if(this.settings.fragmentsEnabled&&!this.fragmentsSupported)throw new Error('The public Mihomo core does not implement this APK’s custom fragments. Activate fragments only with a verified compatible custom core');
    if(this.settings.routingMode==='subscription')throw new Error('Subscription rules and groups are not reconstructed yet; select Iran or global routing');
    this.busy=true;this.status='connecting';this.error=null;this.publish();
    try{
      await fs.access(this.corePath);await checkPort(this.settings.mixedPort);await checkPort(this.settings.controllerPort);
      this.secret=crypto.randomBytes(32).toString('hex');this.controller=new Controller(this.settings.controllerPort,this.secret);
      let geoipAvailable=false;try{await fs.copyFile(path.join(path.dirname(this.corePath),'GEOIP.dat'),path.join(this.dataDir,'GEOIP.dat'));geoipAvailable=true;}catch(e){if(e.code!=='ENOENT')throw e;}
      const file=path.join(this.dataDir,'runtime.yaml'),config=generateConfig(this.settings,this.proxyList(),this.secret,this.selectedServer,{geoipAvailable,fragmentsSupported:this.fragmentsSupported});await fs.writeFile(file,stringify(config),{mode:0o600});if(this.shuttingDown)throw new Error('Connection cancelled');await this.testConfig(file);if(this.shuttingDown)throw new Error('Connection cancelled');
      const child=this.spawnCore(['-d',this.dataDir,'-f',file]);this.process=child;this.capture(child);
      let failure;child.once('error',()=>{failure=new Error('Could not launch Mihomo core');});child.once('exit',(code,signal)=>{failure=new Error(`Core exited (${signal||code})`);if(this.process===child){this.process=null;if(this.status==='connected'){this.status='disconnected';this.error=failure.message;this.publish();}}});
      let version;for(let i=0;i<50;i++){
        if(this.shuttingDown)throw new Error('Connection cancelled');if(failure)throw failure;
        try{version=await this.controller.version();if(version&&typeof version.version==='string')break;}catch{}
        await sleep(120);
      }
      if(!version||typeof version.version!=='string')throw new Error('Core controller did not become ready');
      await this.controller.select(this.selectedServer||this.proxyList()[0].name,this.settings.mode==='global'?'GLOBAL':'AZADNET');this.coreVersion=version.version;this.status='connected';this.log(`Mihomo ${this.coreVersion} ready. Proxy: 127.0.0.1:${this.settings.mixedPort}`);
    }catch(e){await this.terminate();this.status='disconnected';this.error=e.code==='ENOENT'?'Mihomo core was not found':e.message;this.log(this.error);throw new Error(this.error);}
    finally{this.busy=false;this.publish();}
    return this.getState();
  }
  async terminate(){const child=this.process;this.process=null;this.controller=null;if(!child)return;
    await new Promise(resolve=>{let ended=false;const finish=()=>{if(ended)return;ended=true;clearTimeout(timer);resolve();};child.once('exit',finish);const timer=setTimeout(()=>{try{child.kill('SIGKILL');}catch{}finish();},2000);try{child.kill();}catch{finish();}if(child.exitCode!==null&&child.exitCode!==undefined)finish();});
  }
  async stop(){if(this.busy)throw new Error('Connection operation in progress');this.speedTestAbort?.abort();this.busy=true;this.status='disconnecting';this.publish();try{await this.terminate();this.status='disconnected';this.log('Disconnected');}finally{this.busy=false;this.publish();}return this.getState();}
  async shutdown(){this.shuttingDown=true;this.speedTestAbort?.abort();if(this.validationProcess){try{this.validationProcess.kill();}catch{}}await this.terminate();if(this.startPromise){try{await this.startPromise;}catch{}}await this.terminate();this.status='disconnected';this.busy=false;this.publish();}
  async traffic(){if(this.status!=='connected'||!this.controller)return {upload:0,download:0,connections:0};const result=await this.controller.traffic();this.emit('traffic',result);return result;}
  async testServers(){
    if(this.speedTesting)throw new Error('Wait for the speed test to finish before testing servers');
    if(this.testing)throw new Error('Server tests already running');const alreadyConnected=this.status==='connected';this.testing=true;this.publish();
    try{
      if(!alreadyConnected)await this.start();const names=this.proxyList().map(p=>p.name);let cursor=0;
      const worker=async()=>{while(cursor<names.length){const name=names[cursor++];if(!this.controller)break;try{const result=await this.controller.delay(name);this.delays.set(name,Number.isFinite(result.delay)?result.delay:null);}catch{this.delays.set(name,-1);}this.publish();}};
      await Promise.all(Array.from({length:Math.min(5,names.length)},worker));return this.getState();
    }finally{if(!alreadyConnected&&this.status==='connected')await this.stop();this.testing=false;this.publish();}
  }
  async speedTest({bytes=1048576}={}){
    if(this.shuttingDown||this.busy||this.testing||this.speedTesting)throw new Error('Another connection operation is in progress');
    if(this.status!=='connected'||!this.controller)throw new Error('Connect before running a speed test');
    this.speedTesting=true;this.speedTestAbort=new AbortController();this.publish();
    try{const result=await downloadSpeed({proxyPort:this.settings.mixedPort,bytes,signal:this.speedTestAbort.signal});this.emit('speedTest',result);return result;}
    finally{this.speedTesting=false;this.speedTestAbort=null;this.publish();}
  }
}
module.exports=Service;module.exports.Service=Service;module.exports.fetchSubscription=fetchSubscription;
