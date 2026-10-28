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
const {sharingInfo,sharingText}=require('./sharing.cjs');
const {OfficialLicense}=require('./official-license.cjs');
const {OfflineTransfer}=require('./offline-transfer.cjs');
const {parseWindscribeImport}=require('./windscribe-import.cjs');
const {WindscribeRuntime,protocolOf,isExternal}=require('./windscribe-runtime.cjs');
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
function fingerprint(proxy){const order=v=>Array.isArray(v)?v.map(order):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).filter(k=>k!=='name').sort().map(k=>[k,order(v[k])])):v;return crypto.createHash('sha256').update(JSON.stringify(order(proxy))).digest('hex');}
async function atomicJson(file,value){const text=JSON.stringify(value,null,2);if(Buffer.byteLength(text)>16*1024*1024)throw new Error('Saved state exceeds 16 MiB; import fewer profiles');const tmp=`${file}.${crypto.randomBytes(5).toString('hex')}.tmp`;await fs.writeFile(tmp,text,{mode:0o600});try{await fs.rename(tmp,file);}catch(e){await fs.rm(tmp,{force:true});throw e;}}
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
  constructor({dataDir,corePath,emit=()=>{},spawnProcess=spawn,fetchText=fetchSubscription,fragmentsSupported=false,officialLicense=new OfficialLicense(),delayUrl,openvpnIdentitySupported=false,windscribeRuntime}={}){
    if(!dataDir)throw new Error('dataDir is required');
    this.dataDir=dataDir;this.file=path.join(dataDir,'state.json');this.corePath=corePath||process.env.AZADNET_CORE_PATH||path.join(process.resourcesPath||path.join(__dirname,'..','..','resources'),'core',process.platform==='win32'?'mihomo.exe':'mihomo');this.emit=emit;this.spawnProcess=spawnProcess;this.fetchText=fetchText;this.fragmentsSupported=fragmentsSupported===true;this.shuttingDown=false;this.startPromise=null;this.validationProcess=null;
    this.settings={...structuredClone(DEFAULT_SETTINGS),lanPassword:crypto.randomBytes(12).toString('base64url')};this.subscriptions=[];this.selectedServer=null;this.status='disconnected';this.coreVersion=null;this.error=null;this.logs=[];this.process=null;this.controller=null;this.secret='';this.delays=new Map();this.busy=false;this.testing=false;this.speedTesting=false;this.speedTestAbort=null;
    this.officialLicense=officialLicense;this.officialLicenseStatus=null;this.licenseTimer=null;this.checkingLicense=false;
    this.offlineTransfer=new OfflineTransfer({dataDir});this.offlineLicenseStatus=null;this.activeTun=false;this.delayUrl=delayUrl;
    this.openvpnIdentitySupported=openvpnIdentitySupported;this.nativeVpn=false;this.transportTimer=null;this.checkingTransport=false;
    this.windscribe=windscribeRuntime||new WindscribeRuntime({dataDir,corePath:this.corePath,log:line=>this.log(line),onFailure:error=>this.transportFailed(error)});
  }
  async init(){
    await fs.mkdir(this.dataDir,{recursive:true,mode:0o700});
    // A generated core configuration is never a persistent account store.
    await fs.rm(path.join(this.dataDir,'runtime.yaml'),{force:true});
    try{
      const stat=await fs.stat(this.file);if(stat.size>16*1024*1024)throw new Error('Saved state exceeds size limit');
      const saved=JSON.parse(await fs.readFile(this.file,'utf8'));this.settings=validateSettings(saved.settings||{},this.settings);if(!this.settings.lanPassword)this.settings.lanPassword=crypto.randomBytes(12).toString('base64url');
      if(!Array.isArray(saved.subscriptions)||saved.subscriptions.length>100)throw new Error('Invalid saved subscriptions');
      this.subscriptions=saved.subscriptions.filter(s=>s.source!=='windscribe-account').map(s=>{
        if(typeof s.id!=='string'||typeof s.name!=='string'||!Array.isArray(s.proxies)||s.proxies.length>10000)throw new Error('Invalid saved subscription');
        if(s.url){const u=new URL(s.url);if(u.protocol!=='https:'||u.username||u.password)throw new Error('Invalid saved subscription URL');}
        return {...s,proxies:s.proxies.map((p,i)=>validateProxy(p,i+1))};
      });
      this.selectedServer=typeof saved.selectedServer==='string'?saved.selectedServer:null;
    }catch(e){if(e.code!=='ENOENT'){this.log('Saved settings could not be loaded; defaults restored.');this.error='Saved settings could not be loaded';this.settings={...structuredClone(DEFAULT_SETTINGS),lanPassword:crypto.randomBytes(12).toString('base64url')};this.subscriptions=[];}}
    try{await this.windscribe.recover();}catch{this.status='cleanup-required';this.error='اتصال IKEv2 قبلی پاک‌سازی نشد؛ وضعیت VPN سیستم را بررسی کنید.';this.log(this.error);}
    this.publish();return this.getState();
  }
  proxyList(){return this.subscriptions.flatMap(s=>s.proxies);}
  serverSource(name=this.selectedServer){const target=name||this.proxyList()[0]?.name;return this.subscriptions.find(s=>s.proxies.some(p=>p.name===target))?.source;}
  isOfficialServer(name=this.selectedServer){return ['official-windows','offline-transfer'].includes(this.serverSource(name));}
  async checkOfficialLicense(){const status=await this.officialLicense.status();this.officialLicenseStatus=status;this.publish();return status;}
  async checkOfflineLicense(){this.offlineLicenseStatus=await this.offlineTransfer.status();this.publish();return this.offlineLicenseStatus;}
  async requireOfficialLicense(name=this.selectedServer){
    const source=this.serverSource(name);
    if(source==='offline-transfer'){if(!(await this.checkOfflineLicense()).active)throw new Error('اعتبار بستهٔ آفلاین پایان یافته یا تأیید نشد؛ بستهٔ معتبر جدید وارد کنید.');}
    else if(source==='official-windows'&&!(await this.checkOfficialLicense()).active)throw new Error('لایسنس نسخهٔ رسمی ویندوز فعال نیست؛ سرورهای آن قابل استفاده نیستند.');
  }
  async createOfflineRequest(){return this.offlineTransfer.request();}
  async exportOffline(requestText){
    const result=await this.officialLicense.servers();this.officialLicenseStatus=result.license;this.publish();
    if(!result.license.active)throw new Error('صادرات آفلاین به لایسنس فعال نسخهٔ رسمی ویندوز نیاز دارد.');
    if(result.error||!Array.isArray(result.configs)||!result.configs.length)throw new Error('ابتدا سرورهای نسخهٔ رسمی را به‌روز کنید.');
    const parsed=parseSubscription(JSON.stringify(result.configs));
    const exported=await this.offlineTransfer.export(requestText,{license:result.license,proxies:parsed.proxies});
    return {...exported,warnings:parsed.warnings};
  }
  async importOffline(text,trustedFingerprint){
    this.requireIdle();this.busy=true;
    try{const opened=await this.offlineTransfer.accept(text,trustedFingerprint);const existing=this.subscriptions.find(s=>s.source==='offline-transfer');const result=await this.storeImport(JSON.stringify({proxies:opened.proxies}),'سرورهای انتقال آفلاین',undefined,existing,'offline-transfer');this.offlineLicenseStatus=opened.license;return result;}
    finally{this.busy=false;this.publish();}
  }
  async importOfficialServers(){
    this.requireIdle();this.busy=true;
    try{
      const result=await this.officialLicense.servers();this.officialLicenseStatus=result.license;
      if(!result.license.active)throw new Error('ابتدا لایسنس را در نسخهٔ رسمی ویندوز روی همین کامپیوتر فعال کنید.');
      if(result.error||!Array.isArray(result.configs)||!result.configs.length)throw new Error('سرور ذخیره‌شده پیدا نشد؛ ابتدا در نسخهٔ رسمی فهرست سرورها را به‌روز کنید.');
      const existing=this.subscriptions.find(s=>s.source==='official-windows');
      const imported=await this.storeImport(JSON.stringify(result.configs),'سرورهای نسخهٔ رسمی ویندوز',undefined,existing,'official-windows');
      this.publish();return {...imported,cachedAt:result.cachedAt};
    }finally{this.busy=false;this.publish();}
  }
  async importWindscribe(files,options){
    this.requireIdle();this.busy=true;
    try{
      const entries=parseWindscribeImport(files,options),replace=new Map();
      for(const entry of entries){const old=this.subscriptions.find(s=>s.source==='windscribe'&&s.name.toLowerCase()===`Windscribe · ${entry.label}`.toLowerCase());if(old)replace.set(entry.label,old);}
      const replacedIds=new Set([...replace.values()].map(s=>s.id));
      const next=this.subscriptions.filter(s=>!replacedIds.has(s.id));
      const used=new Set(['AZADNET','DIRECT','REJECT','GLOBAL',...next.flatMap(s=>s.proxies.map(p=>p.name))]);
      const warnings=[];let count=0;
      for(const entry of entries){
        const old=replace.get(entry.label);
        const proxies=entry.proxies.map((p,index)=>{const base=old?.proxies[index]?.name||p.name;let name=base;for(let n=2;used.has(name);n++)name=`${base} (${n})`;used.add(name);return validateProxy({...p,name},index+1);});
        count+=proxies.length;warnings.push(...entry.warnings.map(message=>`${entry.label}: ${message}`));
        next.push({id:old?.id||crypto.randomUUID(),name:`Windscribe · ${entry.label}`,source:'windscribe',protocol:entry.protocol,proxies,updatedAt:new Date().toISOString()});
      }
      if(next.length>100||next.reduce((n,s)=>n+s.proxies.length,0)>20000)throw new Error('Profile/server limit exceeded');
      const selected=next.some(s=>s.proxies.some(p=>p.name===this.selectedServer))?this.selectedServer:next[0]?.proxies[0]?.name||null;
      await atomicJson(this.file,this.savedState(next,selected));
      this.subscriptions=next;this.selectedServer=selected;this.publish();
      return {count,added:entries.length-replace.size,updated:replace.size,warnings};
    }finally{this.busy=false;this.publish();}
  }
  windscribeAvailability(){return this.windscribe.availability();}
  async installWindscribeAccount({proxy,accountId,target,expiresAt=null}){
    this.requireIdle();
    if(!(/^[a-f0-9]{64}$/).test(accountId)||!target||typeof target.locationId!=='string')throw new Error('Invalid account connection');
    const next=this.subscriptions.filter(s=>s.source!=='windscribe-account'),used=new Set(next.flatMap(s=>s.proxies.map(p=>p.name)));
    const value=validateProxy(proxy,1),base=value.name;for(let n=2;used.has(value.name);n++)value.name=`${base} (${n})`;
    if(next.length>=100)throw new Error('Profile limit exceeded');
    if(expiresAt!=null&&(!Number.isSafeInteger(expiresAt)||expiresAt<=Date.now()))throw new Error('تنظیمات اتصال حساب منقضی شده است؛ دوباره متصل شوید.');
    next.push({id:crypto.randomUUID(),name:'Windscribe · اتصال حساب',source:'windscribe-account',protocol:target.protocol,proxies:[value],accountId,target:{...target},expiresAt,updatedAt:new Date().toISOString()});
    await atomicJson(this.file,this.savedState(next,value.name));this.subscriptions=next;this.selectedServer=value.name;this.publish();
  }
  async removeWindscribeAccount(accountId){
    const own=this.subscriptions.filter(s=>s.source==='windscribe-account'&&s.accountId===accountId);if(!own.length)return;
    if(own.some(s=>s.proxies.some(p=>p.name===this.selectedServer))&&this.status!=='disconnected')await this.stop();
    this.subscriptions=this.subscriptions.filter(s=>!own.includes(s));
    if(!this.proxyList().some(p=>p.name===this.selectedServer))this.selectedServer=this.proxyList()[0]?.name||null;
    await fs.rm(path.join(this.dataDir,'runtime.yaml'),{force:true});await this.persist();this.publish();
  }
  startAccountExpiryMonitor(){
    clearTimeout(this.accountExpiryTimer);this.accountExpiryTimer=null;
    const profile=this.subscriptions.find(s=>s.source==='windscribe-account'&&s.proxies.some(p=>p.name===this.selectedServer));if(!profile?.expiresAt)return;
    const name=this.selectedServer;
    const expire=async()=>{
      if(this.status!=='connected'||this.selectedServer!==name)return;
      if(this.busy){this.accountExpiryTimer=setTimeout(expire,250);this.accountExpiryTimer.unref?.();return;}
      try{await this.stop();this.error='مهلت نوسازی کلید این اتصال Windscribe رسید؛ برای ادامه دوباره متصل شوید.';this.log(this.error);this.publish();}catch{}
    };
    this.accountExpiryTimer=setTimeout(expire,Math.max(1,profile.expiresAt-Date.now()));this.accountExpiryTimer.unref?.();
  }
  async transportFailed(error){
    if(this.status!=='connected'||this.shuttingDown)return;
    try{await this.terminate();this.status='disconnected';}catch{this.status='cleanup-required';}
    this.error=error.message;this.log(this.error);this.publish();
  }
  startTransportMonitor(){
    this.stopTransportMonitor();if(!this.nativeVpn)return;
    this.transportTimer=setInterval(async()=>{if(this.checkingTransport||this.busy||this.shuttingDown||!this.nativeVpn)return;this.checkingTransport=true;try{if(!(await this.windscribe.native.status()).connected)await this.transportFailed(new Error('اتصال IKEv2 سیستم قطع شد.'));}catch{await this.transportFailed(new Error('وضعیت اتصال IKEv2 سیستم تأیید نشد.'));}finally{this.checkingTransport=false;}},5000);this.transportTimer.unref?.();
  }
  stopTransportMonitor(){if(this.transportTimer)clearInterval(this.transportTimer);this.transportTimer=null;}
  startLicenseMonitor(){
    this.stopLicenseMonitor();
    this.licenseTimer=setInterval(()=>{void this.enforceOfficialLicense();},60000);this.licenseTimer.unref?.();
  }
  stopLicenseMonitor(){if(this.licenseTimer)clearInterval(this.licenseTimer);this.licenseTimer=null;}
  async enforceOfficialLicense(){
    if(this.checkingLicense||this.shuttingDown||this.busy||this.status!=='connected'||!this.isOfficialServer())return;
    this.checkingLicense=true;
    try{await this.requireOfficialLicense();}catch{
      if(this.shuttingDown||!this.isOfficialServer())return;
      await this.terminate();this.status='disconnected';this.error='اعتبار اشتراک یا بستهٔ آفلاین تأیید نشد؛ اتصال آن قطع شد.';this.log(this.error);this.publish();
    }finally{this.checkingLicense=false;}
  }
  getState(){return {settings:structuredClone(this.settings),subscriptions:this.subscriptions.map(s=>({id:s.id,name:s.name,source:s.source,protocol:s.protocol,url:s.url?new URL(s.url).origin:undefined,count:s.proxies.length,updatedAt:s.updatedAt})),servers:this.subscriptions.flatMap(s=>s.proxies.map(p=>({name:p.name,type:p.type,server:p.server,port:p.port,protocol:protocolOf(p)||p.type,source:s.source,subscriptionId:s.id,delay:this.delays.get(p.name)??null}))),selectedServer:this.selectedServer,status:this.status,activeTun:this.activeTun,nativeVpn:this.nativeVpn,coreVersion:this.coreVersion,error:this.error,testing:this.testing,speedTesting:this.speedTesting,officialLicense:this.officialLicenseStatus,offlineLicense:this.offlineLicenseStatus,capabilities:{fragmentsSupported:this.fragmentsSupported,openvpnIdentitySupported:this.openvpnIdentitySupported,platform:process.platform}};}
  publish(){this.emit('state',this.getState());}
  log(line){
    let text=String(line).replace(/\u001b\[[0-9;]*m/g,'').replace(/[\x00-\x08\x0b-\x1f]/g,'').trim().slice(0,2000);if(!text)return;
    if(this.secret)text=text.split(this.secret).join('[redacted]');
    if(this.settings.lanPassword?.length>=5)text=text.split(this.settings.lanPassword).join('[redacted]');
    for(const p of this.proxyList())for(const key of ['password','username','uuid','private-key','pre-shared-key','key','tls-auth','tls-crypt','tls-crypt-v2'])if(typeof p[key]==='string'&&p[key].length>5)text=text.split(p[key]).join('[redacted]');
    text=text.replace(/(?:vmess|vless|trojan|ss|hy2|hysteria2|tuic|wireguard|wg):\/\/\S+/gi,'[proxy URI redacted]').replace(/(password|secret|token|auth(?:orization)?|private-key)\s*[:=]\s*[^\s,]+/gi,'$1=[redacted]');
    const entry={time:new Date().toISOString(),message:text};this.logs.push(entry);if(this.logs.length>500)this.logs.splice(0,this.logs.length-500);this.emit('log',entry);
  }
  getLogs(){return this.logs.map(x=>({...x}));}
  savedState(subscriptions=this.subscriptions,selectedServer=this.selectedServer){
    const saved=subscriptions.filter(s=>s.source!=='windscribe-account');
    return {version:1,settings:this.settings,subscriptions:saved,selectedServer:saved.some(s=>s.proxies.some(p=>p.name===selectedServer))?selectedServer:saved[0]?.proxies[0]?.name||null};
  }
  async persist(){await atomicJson(this.file,this.savedState());}
  requireIdle(){if(this.busy||this.testing||this.sharingUpdating||this.status!=='disconnected')throw new Error('Disconnect before changing configuration');}
  getSharing(){return {...sharingInfo(this.settings,this.status),updating:!!this.sharingUpdating};}
  getSharingText(){return sharingText(this.getSharing());}
  async updateSharing(patch,{regeneratePassword=false}={}){
    if(this.busy||this.testing||this.speedTesting||this.sharingUpdating||this.shuttingDown)throw new Error('عملیات دیگری در حال انجام است؛ کمی صبر کنید.');
    if(!patch||typeof patch!=='object'||Array.isArray(patch)||Object.keys(patch).some(k=>!['allowLan','lanPasswordRequired','lanUsername','lanPassword'].includes(k)))throw new Error('تنظیمات اشتراک‌گذاری نامعتبر است.');
    const previous=structuredClone(this.settings);
    const next=validateSettings({...patch,...(regeneratePassword?{lanPassword:crypto.randomBytes(12).toString('base64url')}: {})},this.settings);
    if(next.allowLan&&next.lanPasswordRequired&&next.lanPassword.length<8)throw new Error('رمز عبور اشتراک‌گذاری باید حداقل ۸ کاراکتر باشد.');
    const reconnect=this.status==='connected';this.sharingUpdating=true;this.publish();
    try{
      if(reconnect)await this.stop();
      if(this.shuttingDown)throw new Error('برنامه در حال بسته‌شدن است.');
      this.settings=next;await this.persist();
      if(reconnect)await this.start();
      return this.getSharing();
    }catch(error){
      this.settings=previous;await this.persist();
      if(reconnect&&!this.shuttingDown&&this.status==='disconnected')try{await this.start();}catch{this.log('Could not restore connection after sharing update');}
      throw error;
    }finally{this.sharingUpdating=false;this.publish();}
  }
  async saveSettings(patch){this.requireIdle();this.busy=true;try{this.settings=validateSettings(patch,this.settings);await this.persist();this.publish();return this.getState();}finally{this.busy=false;}}
  async storeImport(text,name,url,existing,source){
    if(!existing&&this.subscriptions.length>=100)throw new Error('At most 100 subscriptions are supported');
    if(typeof name!=='string'||!name.trim()||name.length>180)throw new Error('Invalid subscription name');
    const {proxies,warnings}=parseSubscription(text),others=this.subscriptions.filter(s=>s.id!==existing?.id).flatMap(s=>s.proxies),used=new Set(['AZADNET','DIRECT','REJECT','GLOBAL',...others.map(p=>p.name)]),renames=new Map();
    if(others.length+proxies.length>20000)throw new Error('At most 20000 servers are supported');
    const previous=new Map((existing?.proxies||[]).map(p=>[fingerprint(p),p.name]));
    for(const p of proxies){const original=p.name,preferred=previous.get(fingerprint(p))||original;let unique=preferred;for(let n=2;used.has(unique);n++)unique=`${preferred} (${n})`;p.name=unique;used.add(unique);if(!renames.has(original))renames.set(original,unique);}
    for(const p of proxies)if(p['dialer-proxy']&&renames.has(p['dialer-proxy']))p['dialer-proxy']=renames.get(p['dialer-proxy']);
    const s={id:existing?.id||crypto.randomUUID(),name:name.trim(),proxies,updatedAt:new Date().toISOString(),...(url?{url}:{}),...((source||existing?.source)?{source:source||existing.source}:{})};
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
    this.requireIdle();const s=this.subscriptions.find(s=>s.id===id);if(!s)throw new Error('Subscription not found');if(s.source==='official-windows')return this.importOfficialServers();if(s.source==='offline-transfer')throw new Error('برای به‌روزرسانی، بستهٔ انتقال جدیدی از ویندوز وارد کنید.');if(!s.url)throw new Error('This subscription was imported from text and has no refresh URL');
    this.busy=true;try{this.log('Refreshing subscription over HTTPS…');const text=await this.fetchText(s.url);return await this.storeImport(text,s.name,s.url,s);}finally{this.busy=false;}
  }
  async removeSubscription(id){this.requireIdle();if(typeof id!=='string')throw new Error('Invalid subscription id');const index=this.subscriptions.findIndex(s=>s.id===id);if(index<0)throw new Error('Subscription not found');this.subscriptions.splice(index,1);if(!this.proxyList().some(p=>p.name===this.selectedServer))this.selectedServer=this.proxyList()[0]?.name||null;this.busy=true;try{await this.persist();this.publish();return this.getState();}finally{this.busy=false;}}
  async selectServer(name){
    if(this.status==='cleanup-required')throw new Error('ابتدا قطع اتصال IKEv2 سیستم را دوباره امتحان کنید.');
    if(this.testing)throw new Error('Wait for the server test to finish before changing servers');
    if(this.speedTesting)throw new Error('Wait for the speed test to finish before changing servers');
    if(this.busy)throw new Error('Connection operation in progress');if(!this.proxyList().some(p=>p.name===name))throw new Error('Server not found');
    await this.requireOfficialLicense(name);
    const target=this.proxyList().find(p=>p.name===name),current=this.proxyList().find(p=>p.name===this.selectedServer);
    if(target.type==='openvpn'&&target['verify-x509-name']&&!this.openvpnIdentitySupported)throw new Error('برای این پروفایل، هستهٔ جدید با بررسی نام گواهی لازم است.');
    if(this.status==='connected'&&(isExternal(current)||isExternal(target))){
      const old=this.selectedServer;await this.stop();this.selectedServer=name;
      try{await this.start();await this.persist();return this.getState();}
      catch(error){this.selectedServer=old;try{await this.start();}catch{this.log('The previous transport could not be restored.');}throw error;}
    }
    if(this.status==='connected'){
      try{const result=await this.controller.delay(name,{timeout:this.probeTimeout(name)});if(!Number.isFinite(result?.delay)||result.delay<=0)throw new Error('No response');this.delays.set(name,result.delay);}
      catch{this.delays.set(name,-1);this.publish();throw new Error('این سرور پاسخ نداد؛ سرور فعلی حفظ شد. سرور دیگری انتخاب کنید.');}
      await this.controller.select(name,this.settings.mode==='global'?'GLOBAL':'AZADNET');
    }
    this.selectedServer=name;await this.persist();this.publish();return this.getState();
  }
  probeTimeout(name){const p=this.proxyList().find(x=>x.name===name);return p?.type==='openvpn'?30000:p?.type==='wireguard'?10000:p?.type==='ikev2'?6000:3000;}
  spawnCore(args){return this.spawnProcess(this.corePath,args,{cwd:this.dataDir,windowsHide:true,stdio:['ignore','pipe','pipe'],shell:false});}
  capture(child){for(const stream of [child.stdout,child.stderr]){if(!stream)continue;let pending='';stream.on('data',chunk=>{pending+=chunk.toString();const lines=pending.split(/\r?\n/);pending=lines.pop().slice(-4000);for(const line of lines)this.log(line);});stream.on('end',()=>{if(pending)this.log(pending);});}}
  async testConfig(file){return new Promise((resolve,reject)=>{
    const child=this.spawnCore(['-t','-d',this.dataDir,'-f',file]);this.validationProcess=child;this.capture(child);let settled=false;
    const done=(err)=>{if(settled)return;settled=true;clearTimeout(timer);if(this.validationProcess===child)this.validationProcess=null;err?reject(err):resolve();};
    const timer=setTimeout(()=>{child.kill();done(new Error('Core configuration validation timed out'));},15000);
    child.once('error',()=>done(new Error('Could not launch Mihomo core')));child.once('exit',(code,signal)=>done(code===0?null:new Error(`Mihomo rejected configuration (${signal||code}); see logs`)));
  });}
  async start({testOnly=false,testServerName}={}){
    if(this.shuttingDown)throw new Error('Application is shutting down');
    if(this.startPromise)throw new Error('Connection operation in progress');
    this.startPromise=this.runStart({testOnly,testServerName});try{return await this.startPromise;}finally{this.startPromise=null;}
  }
  async runStart({testOnly=false,testServerName}={}){
    if(this.status==='cleanup-required')throw new Error('ابتدا قطع اتصال IKEv2 سیستم را دوباره امتحان کنید.');
    if(this.busy)throw new Error('Connection operation in progress');if(this.status==='connected')return this.getState();if(!this.proxyList().length)throw new Error('Import a subscription or server first');
    if(this.settings.fragmentsEnabled&&!this.fragmentsSupported)throw new Error('The public Mihomo core does not implement this APK’s custom fragments. Activate fragments only with a verified compatible custom core');
    if(this.settings.routingMode==='subscription')throw new Error('Subscription rules and groups are not reconstructed yet; select Iran or global routing');
    if(this.proxyList().some(p=>p.type==='openvpn'&&p['verify-x509-name'])&&!this.openvpnIdentitySupported)throw new Error('برای این پروفایل، هستهٔ جدید با بررسی نام گواهی لازم است.');
    this.busy=true;this.status='connecting';this.error=null;this.publish();
    try{
      const selectedProfile=this.proxyList().find(p=>p.name===(testServerName||this.selectedServer))||this.proxyList()[0];
      await this.requireOfficialLicense(selectedProfile.name);
      await fs.access(this.corePath);await checkPort(this.settings.mixedPort);await checkPort(this.settings.controllerPort);
      const transport=await this.windscribe.prepare(selectedProfile,this.proxyList(),{testOnly});
      this.nativeVpn=transport.nativeVpn;
      const selected=testOnly?(transport.proxies.find(p=>p.name===selectedProfile.name)||transport.proxies[0])?.name:selectedProfile.name;
      if(!selected)throw new Error('این پروتکل برای سنجش به اتصال جداگانه نیاز دارد.');
      this.secret=crypto.randomBytes(32).toString('hex');this.controller=new Controller(this.settings.controllerPort,this.secret,{delayUrl:this.delayUrl});
      let geoipAvailable=false;try{await fs.copyFile(path.join(path.dirname(this.corePath),'GEOIP.dat'),path.join(this.dataDir,'GEOIP.dat'));geoipAvailable=true;}catch(e){if(e.code!=='ENOENT')throw e;}
      // Latency tests need only the local listener, even when saved TUN settings
      // cannot be enabled. Never change system routes just to test servers.
      const file=path.join(this.dataDir,'runtime.yaml'),config=generateConfig(testOnly||this.nativeVpn?{...this.settings,tun:false}:this.settings,transport.proxies,this.secret,selected,{geoipAvailable,fragmentsSupported:this.fragmentsSupported});
      if(config.tun&&transport.routeExcludes.length)config.tun['route-exclude-address']=transport.routeExcludes;
      await fs.writeFile(file,stringify(config),{mode:0o600});if(this.shuttingDown)throw new Error('Connection cancelled');await this.testConfig(file);if(this.shuttingDown)throw new Error('Connection cancelled');
      const child=this.spawnCore(['-d',this.dataDir,'-f',file]);this.process=child;this.capture(child);
      let failure;child.once('error',()=>{failure=new Error('Could not launch Mihomo core');});child.once('exit',(code,signal)=>{failure=new Error(`Core exited (${signal||code})`);if(this.process===child){this.process=null;this.activeTun=false;if(this.status==='connected')void this.transportFailed(failure);}});
      let version;for(let i=0;i<50;i++){
        if(this.shuttingDown)throw new Error('Connection cancelled');if(failure)throw failure;
        try{version=await this.controller.version();if(version&&typeof version.version==='string')break;}catch{}
        await sleep(120);
      }
      if(!version||typeof version.version!=='string')throw new Error('Core controller did not become ready');
      if(this.settings.tun&&!testOnly&&!this.nativeVpn){
        let runtime;
        for(let i=0;i<10;i++){runtime=await this.controller.configs();if(runtime?.tun?.enable===true)break;await sleep(120);}
        if(runtime?.tun?.enable!==true||runtime.tun['auto-route']!==true){
          throw new Error(process.platform==='win32'?'رابط TUN فعال نشد. برنامه را کامل ببندید و AzadNet.exe را با Run as administrator اجرا کنید؛ سپس دوباره متصل شوید. جزئیات در گزارش اتصال است.':'رابط TUN فعال نشد. پس از نصب بسته، دستور sudo /opt/azadnet/enable-tun.sh را اجرا کنید و دوباره متصل شوید. جزئیات در گزارش اتصال است.');
        }
        this.activeTun=true;
      }
      await this.controller.select(selected,this.settings.mode==='global'?'GLOBAL':'AZADNET');
      if(!testOnly){
        try{const result=await this.controller.delay(selected,{timeout:this.probeTimeout(selected)});if(!Number.isFinite(result?.delay)||result.delay<=0)throw new Error('No response');this.delays.set(selected,result.delay);}
        catch{this.delays.set(selected,-1);throw new Error('سرور انتخاب‌شده پاسخ نداد. «سنجش و انتخاب سرور پاسخ‌گو» را بزنید و پس از پایان دوباره متصل شوید.');}
      }
      if(this.shuttingDown)throw new Error('Connection cancelled');if(failure)throw failure;if(this.windscribe.failure)throw this.windscribe.failure;
      this.coreVersion=version.version;this.status='connected';if(!testOnly){this.startLicenseMonitor();this.startAccountExpiryMonitor();}this.startTransportMonitor();this.log(`Mihomo ${this.coreVersion} ready. Proxy: 127.0.0.1:${this.settings.mixedPort}; TUN: ${this.activeTun?'active':'off'}; native IKEv2: ${this.nativeVpn?'active':'off'}`);
    }catch(e){let cleanupFailed=false;try{await this.terminate();}catch{cleanupFailed=true;}this.status=cleanupFailed?'cleanup-required':'disconnected';this.error=(e.code==='ENOENT'?'Mihomo core was not found':e.message)+(cleanupFailed?'؛ قطع اتصال IKEv2 سیستم تأیید نشد.':'');this.log(this.error);throw new Error(this.error);}
    finally{this.busy=false;this.publish();}
    return this.getState();
  }
  async terminate(){this.stopLicenseMonitor();this.stopTransportMonitor();clearTimeout(this.accountExpiryTimer);this.accountExpiryTimer=null;this.activeTun=false;const child=this.process;this.process=null;this.controller=null;
    if(child)await new Promise(resolve=>{let ended=false;const finish=()=>{if(ended)return;ended=true;clearTimeout(timer);resolve();};child.once('exit',finish);const timer=setTimeout(()=>{try{child.kill('SIGKILL');}catch{}finish();},2000);try{child.kill();}catch{finish();}if(child.exitCode!==null&&child.exitCode!==undefined)finish();});
    await this.windscribe.stop();this.nativeVpn=false;
    if(this.subscriptions.some(s=>s.source==='windscribe-account'))await fs.rm(path.join(this.dataDir,'runtime.yaml'),{force:true});
  }
  async stop(){if(this.busy)throw new Error('Connection operation in progress');this.speedTestAbort?.abort();this.busy=true;this.status='disconnecting';this.publish();try{await this.terminate();this.status='disconnected';this.error=null;this.log('Disconnected');}catch(error){this.status='cleanup-required';this.error='قطع اتصال IKEv2 سیستم تأیید نشد؛ دوباره قطع اتصال را بزنید یا VPN سیستم را بررسی کنید.';this.log(this.error);throw new Error(this.error);}finally{this.busy=false;this.publish();}return this.getState();}
  async shutdown(){this.shuttingDown=true;this.speedTestAbort?.abort();if(this.validationProcess){try{this.validationProcess.kill();}catch{}}try{await this.terminate();}catch{}if(this.startPromise){try{await this.startPromise;}catch{}}try{await this.terminate();this.status='disconnected';}catch(error){this.status='cleanup-required';throw error;}finally{this.busy=false;this.publish();}}
  async traffic(){if(this.status!=='connected'||!this.controller)return {upload:0,download:0,connections:0};const result=await this.controller.traffic();this.emit('traffic',result);return result;}
  async testServers({source}={}){
    if(this.status==='cleanup-required')throw new Error('ابتدا قطع اتصال IKEv2 سیستم را دوباره امتحان کنید.');
    if(this.speedTesting)throw new Error('Wait for the speed test to finish before testing servers');
    const subscriptions=source?this.subscriptions.filter(s=>s.source===source):this.subscriptions;
    if(subscriptions.some(s=>s.source==='official-windows')&&!(await this.checkOfficialLicense()).active)throw new Error('برای آزمون سرورهای نسخهٔ رسمی، لایسنس آن باید فعال باشد.');
    if(subscriptions.some(s=>s.source==='offline-transfer')&&!(await this.checkOfflineLicense()).active)throw new Error('برای آزمون این سرورها، بستهٔ آفلاین باید معتبر باشد.');
    if(this.testing)throw new Error('Server tests already running');
    const alreadyConnected=this.status==='connected',profiles=subscriptions.flatMap(s=>s.proxies);
    const available=profiles.filter(p=>!isExternal(p)||(alreadyConnected&&p.name===this.selectedServer));
    const skipped=profiles.length-available.length;
    if(!available.length)throw new Error('برای سنجش این پروتکل، ابتدا همان پروفایل را انتخاب و متصل کنید.');
    this.testing=true;this.publish();
    try{
      if(!alreadyConnected)await this.start({testOnly:true,testServerName:available[0].name});
      const names=available.map(p=>p.name);let cursor=0;const responding=[];
      const worker=async()=>{while(cursor<names.length){const name=names[cursor++];if(!this.controller)break;try{const result=await this.controller.delay(name,{timeout:this.probeTimeout(name)});if(!Number.isFinite(result?.delay)||result.delay<=0)throw new Error('No response');this.delays.set(name,result.delay);responding.push({name,delay:result.delay});}catch{this.delays.set(name,-1);}this.publish();}};
      await Promise.all(Array.from({length:Math.min(5,names.length)},worker));
      if(this.shuttingDown)throw new Error('Connection cancelled');
      if(!responding.length)throw new Error('هیچ سروری پاسخ نداد؛ تنظیمات و اعتبار اشتراک همان سرویس را بررسی کنید.');
      const current=this.proxyList().find(p=>p.name===this.selectedServer);
      if(!responding.some(p=>p.name===this.selectedServer)&&!(alreadyConnected&&isExternal(current))){
        const best=responding.sort((a,b)=>a.delay-b.delay)[0];await this.requireOfficialLicense(best.name);
        await this.controller.select(best.name,this.settings.mode==='global'?'GLOBAL':'AZADNET');this.selectedServer=best.name;await this.persist();this.log('Selected a responding server after the previous server failed its test.');
      }
      return {...this.getState(),testSummary:{tested:names.length,skipped,responding:responding.length,selectedResponsive:responding.some(p=>p.name===this.selectedServer)}};
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
