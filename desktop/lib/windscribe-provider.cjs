'use strict';
const net=require('node:net');
const {WindscribeError,sessionProfile}=require('./windscribe-account.cjs');
const {parseOpenVPNConfig}=require('./openvpn-config.cjs');
const {validateIKEv2Profile}=require('./native-ikev2.cjs');
const {createDevice,wireguardProfile}=require('./windscribe-wireguard.cjs');
const providerError=message=>new WindscribeError('input',message);
const MODES=['wireguard','udp','tcp','ikev2','stealth','wstunnel'];
const protocolNames={wg:'wireguard',wireguard:'wireguard',udp:'udp',tcp:'tcp',ikev2:'ikev2',stunnel:'stealth',stealth:'stealth',wstunnel:'wstunnel'};
const safeText=(x,max=120)=>typeof x==='string'&&x.length>0&&x.length<=max&&!/[\x00-\x1f\x7f\u202a-\u202e\u2066-\u2069]/.test(x);
const hostname=x=>safeText(x,253)&&/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/i.test(x);
const id=x=>Number.isSafeInteger(x)&&x>0;
function address(x){
  if(typeof x!=='string'||!net.isIP(x)||x.includes('%'))return false;
  if(net.isIP(x)===4)return !/^(?:0\.|10\.|127\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)/.test(x);
  return !/^(?:::|::1|f[cd]|fe[89ab])/i.test(x);
}
function parsePorts(data){
  if(!Array.isArray(data?.portmap)||data.portmap.length>32)throw providerError('نقشهٔ پورت معتبر از Windscribe دریافت نشد.');
  const result={};
  for(const entry of data.portmap){
    const mode=protocolNames[String(entry.protocol||entry.heading||'').toLowerCase()];if(!mode)continue;
    if(!['ip','ip2','ip3','hostname'].includes(entry.use)||!Array.isArray(entry.ports)||entry.ports.length>64)throw providerError('نقشهٔ پورت Windscribe کامل نیست.');
    const advertised=[...new Set(entry.ports.map(Number))];if(!advertised.length||advertised.some(p=>!Number.isInteger(p)||p<1||p>65535))throw providerError('پورت نامعتبر از Windscribe دریافت شد.');
    // New Windscribe ports can require its extra OpenVPN packet obfuscation.
    // The current core supports the standard transports, so honor the API's
    // explicit legacy_ports subset instead of silently dialing incompatible ports.
    let ports=advertised;
    if(Object.hasOwn(entry,'legacy_ports')){
      if(!Array.isArray(entry.legacy_ports)||entry.legacy_ports.length>64||entry.legacy_ports.map(Number).some(p=>!Number.isInteger(p)||!advertised.includes(p)))throw providerError('پورت سازگار در نقشهٔ سرویس معتبر نیست.');
      ports=[...new Set(entry.legacy_ports.map(Number))];
    }
    result[mode]={use:entry.use,ports:mode==='ikev2'?ports.filter(p=>p===500):ports};
  }
  if(!Object.keys(result).length)throw providerError('پروتکل قابل استفاده در نقشهٔ پورت پیدا نشد.');
  return result;
}
function adaptOpenVPNTemplate(template){
  let block=false,maxSessionSeconds=null;
  const text=template.split(/\r?\n/).map(line=>{
    if(/^\s*<\//.test(line)){block=false;return line;}if(/^\s*</.test(line)){block=true;return line;}
    if(!block){const match=/^\s*reneg-sec\s+(\d+)\s*(?:[#;].*)?$/.exec(line);if(match){const seconds=Number(match[1]);if(!Number.isSafeInteger(seconds)||seconds>604800)throw providerError('زمان نوسازی کلید OpenVPN پشتیبانی نمی‌شود.');if(seconds>0)maxSessionSeconds=maxSessionSeconds==null?seconds:Math.min(maxSessionSeconds,seconds);return 'reneg-sec 0';}}
    return line;
  }).join('\n');
  // Mihomo handles server-initiated rekey, but does not expose a client timer.
  // Service enforces this maximum age by closing the generated connection.
  return {text,maxSessionSeconds};
}
function parseCatalog(locationData,serverData,portData){
  if(!Array.isArray(locationData?.locations)||locationData.locations.length>500||!Array.isArray(serverData?.servers)||serverData.servers.length>10000)throw providerError('فهرست سرورهای Windscribe معتبر نیست.');
  const ports=parsePorts(portData),nodes=new Map(),seenServers=new Set();
  for(const server of serverData.servers){
    if(!id(server.id)||!id(server.dc_id)||seenServers.has(server.id)||!hostname(server.host)||!address(server.ip)||server.fd===1)continue;
    seenServers.add(server.id);const node={id:server.id,host:server.host,ip:server.ip,ip2:address(server.ip2)?server.ip2:null,ip3:address(server.ip3)?server.ip3:null,load:Number.isInteger(server.net_load)&&server.net_load>=0&&server.net_load<=100?server.net_load:null,weight:Number.isFinite(server.weight)?server.weight:1};
    if(!nodes.has(server.dc_id))nodes.set(server.dc_id,[]);nodes.get(server.dc_id).push(node);
  }
  const rows=[],seen=new Set();
  for(const location of locationData.locations){
    if(!id(location.id)||!safeText(location.name)||!(/^[A-Z]{2}$/).test(location.country_code)||!Array.isArray(location.datacenters)||location.datacenters.length>500)throw providerError('اطلاعات کشور Windscribe معتبر نیست.');
    for(const dc of location.datacenters){
      if(rows.length>=3000||!id(dc.id)||seen.has(dc.id)||!safeText(dc.city)||!safeText(dc.nick)||!hostname(dc.ovpn_x509))throw providerError('اطلاعات موقعیت Windscribe معتبر نیست.');
      seen.add(dc.id);
      const ownNodes=(nodes.get(dc.id)||[]).filter(n=>n.weight>0).sort((a,b)=>(a.load??101)-(b.load??101)||b.weight-a.weight||a.id-b.id);
      const availableModes=Object.keys(ports).filter(mode=>ports[mode].ports.length&&ownNodes.some(n=>ports[mode].use==='hostname'?hostname(n.host):address(n[ports[mode].use]))&&(mode!=='wireguard'||typeof dc.wg_pubkey==='string'&&/^[A-Za-z0-9+/]{43}=$/.test(dc.wg_pubkey)));
      rows.push({id:String(dc.id),country:location.name,countryCode:location.country_code,city:dc.city,nickname:dc.nick,premium:dc.premium===1,online:dc.status===1,nodes:ownNodes,peerKey:dc.wg_pubkey,x509:dc.ovpn_x509,protocols:availableModes,load:ownNodes.length?Math.round(ownNodes.reduce((sum,n)=>sum+(n.load??0),0)/ownNodes.length):null});
    }
  }
  return {rows,ports};
}
class WindscribeProvider{
  constructor({account,service,now=Date.now}={}){this.account=account;this.service=service;this.now=now;this.identity=null;this.data=null;this.updatedAt=null;this.wgConfig=null;this.busy=false;}
  clear(){this.identity=null;this.data=null;this.updatedAt=null;this.wgConfig=null;}
  requireAccount(){if(!this.account.token||!this.account.profile||!this.account.identity)throw new WindscribeError(701);if(this.account.profile.status!==1)throw providerError('حساب Windscribe اجازهٔ اتصال ندارد؛ وضعیت یا حجم اشتراک را بررسی کنید.');}
  snapshot(){
    const ready=this.account.state().loggedIn&&this.identity===this.account.identity&&this.data;
    return {loaded:!!ready,updatedAt:ready?this.updatedAt:null,ports:ready?Object.fromEntries(Object.entries(this.data.ports).map(([p,v])=>[p,[...v.ports]])):{},locations:ready?this.data.rows.map(r=>({id:r.id,country:r.country,countryCode:r.countryCode,city:r.city,nickname:r.nickname,premium:r.premium,available:r.online&&r.nodes.length>0&&r.protocols.length>0&&this.account.profile.status===1,protocols:r.online?[...r.protocols]:[],nodeCount:r.nodes.length,load:r.load})):[]};
  }
  async authenticated(fn){return this.account.operation(async()=>{this.requireAccount();try{return await fn();}catch(error){if([701,706].includes(error.code)&&this.account.token)await this.account.forget();throw error;}});}
  async fetchLocked(force=false){
    this.requireAccount();if(this.identity!==this.account.identity)this.clear();
    if(!force&&this.data&&this.now()-this.updatedAt<300000)return;
    const locations=await this.account.api('GET','Inventory/locations');
    const servers=await this.account.api('GET','Inventory/servers',{backup:'0'});
    const ports=await this.account.api('GET','PortMap',{version:'6'});
    const parsed=parseCatalog(locations,servers,ports);
    if(this.account.abort?.signal.aborted)throw providerError('دریافت فهرست لغو شد.');
    this.identity=this.account.identity;this.data=parsed;this.updatedAt=this.now();
  }
  async catalog({force=false}={}){return this.authenticated(async()=>{await this.fetchLocked(force===true);return this.snapshot();});}
  async prepareLocked(input){
    if(!input||typeof input.locationId!=='string'||!/^\d{1,12}$/.test(input.locationId)||!MODES.includes(input.protocol))throw providerError('موقعیت و پروتکل Windscribe را انتخاب کنید.');
    await this.fetchLocked();
    const row=this.data.rows.find(r=>r.id===input.locationId),mode=input.protocol,map=this.data.ports[mode];
    // Inventory/servers is authenticated and scoped by Windscribe to the
    // account's entitlement. Global location metadata alone never grants access.
    if(!row||!row.online||!row.nodes.length||!row.protocols.includes(mode)||!map)throw providerError('این موقعیت یا پروتکل در حساب شما در دسترس نیست.');
    const port=input.port==null?map.ports[0]:input.port;
    if(!Number.isInteger(port)||!map.ports.includes(port))throw providerError('پورت انتخاب‌شده در نقشهٔ رسمی این پروتکل نیست.');
    const node=row.nodes.find(n=>map.use==='hostname'?hostname(n.host):address(n[map.use]));if(!node)throw providerError('سرور آماده برای این موقعیت پیدا نشد.');
    const host=map.use==='hostname'?node.host:node[map.use],name=`Windscribe حساب · ${row.country} · ${row.city} · ${row.nickname} · ${mode}`.slice(0,155);
    let proxy,maxSessionSeconds=null;
    if(mode==='wireguard'){
      if(!this.account.device){this.account.device=createDevice();await this.account.save();}
      let candidateConfig=this.wgConfig;
      if(!candidateConfig){
        let result;try{result=await this.account.api('POST','WgConfigs/init',{wg_pubkey:this.account.device.publicKey,device_id:this.account.device.id});}
        catch(error){if(error.code===1313)throw providerError('ظرفیت کلیدهای WireGuard حساب پر است؛ کلیدهای قدیمی را در سایت Windscribe مدیریت کنید یا پروتکل دیگری انتخاب کنید.');throw error;}
        if(!result.config||typeof result.config!=='object')throw providerError('تنظیمات WireGuard از سرویس دریافت نشد.');candidateConfig=result.config;
      }
      proxy=wireguardProfile({device:this.account.device,config:candidateConfig,peerKey:row.peerKey,host,port,name,ipv6:this.service.settings.ipv6});this.wgConfig=candidateConfig;
    }else{
      const credentials=await this.account.loadCredentials(mode);
      if(mode==='ikev2')proxy=validateIKEv2Profile({name,type:'ikev2',server:row.x509,port:500,username:credentials.username,password:credentials.password});
      else{
        const data=await this.account.api('GET','ServerConfigs',{ovpn_version:'2.6'});
        if(typeof data.openvpn!=='string'||!data.openvpn)throw providerError('قالب OpenVPN از سرویس دریافت نشد.');
        const adapted=adaptOpenVPNTemplate(data.openvpn);maxSessionSeconds=adapted.maxSessionSeconds;
        const text=adapted.text+`\nremote ${host} ${port}\nproto ${mode==='udp'?'udp':'tcp-client'}\nverify-x509-name ${row.x509} name\n`;
        proxy=parseOpenVPNConfig(text,{name,auth:credentials}).proxies[0];proxy['windscribe-mode']=mode;
        if(['stealth','wstunnel'].includes(mode))Object.assign(proxy,{'outer-server':host,'outer-port':port,'outer-sni':node.host,'outer-padding':false});
      }
    }
    if(this.account.abort?.signal.aborted)throw providerError('اتصال لغو شد.');
    return {proxy,accountId:this.account.identity,target:{locationId:row.id,protocol:mode,port},expiresAt:maxSessionSeconds?this.now()+maxSessionSeconds*1000:null};
  }
  async connect(input){
    if(this.busy)throw providerError('اتصال Windscribe در حال آماده‌سازی است.');
    if(this.service.busy||this.service.testing||this.service.speedTesting||this.service.sharingUpdating||!['disconnected','connected'].includes(this.service.status))throw providerError('ابتدا عملیات اتصال فعلی را کامل کنید.');
    this.busy=true;
    try{return await this.authenticated(async()=>{
      // Refresh account entitlement before generating a connection; do not use
      // an old catalog after plan/status changes or a revoked session.
      const session=await this.account.api('GET','Session'),profile=sessionProfile(session);
      const crypto=require('node:crypto');if(crypto.createHash('sha256').update(session.user_id).digest('hex')!==this.account.identity)throw new WindscribeError(701);
      this.account.profile=profile;
      if(profile.status!==1){await this.service.removeWindscribeAccount(this.account.identity);this.clear();this.requireAccount();}
      await this.fetchLocked(true);
      const prepared=await this.prepareLocked(input);
      if(this.service.status==='connected')await this.service.stop();
      await this.service.installWindscribeAccount(prepared);
      try{return await this.service.start();}catch(error){this.service.error=error.message;this.service.publish();throw new WindscribeError('local',error.message);}
    });}finally{this.busy=false;}
  }
  async reconnect(){const subscription=this.service.subscriptions.find(s=>s.source==='windscribe-account'&&s.proxies.some(p=>p.name===this.service.selectedServer));if(!subscription||subscription.accountId!==this.account.identity)throw new WindscribeError(701);return this.connect(subscription.target);}
  async forget(identity){this.clear();await this.service.removeWindscribeAccount(identity);}
}
module.exports={WindscribeProvider,parseCatalog,parsePorts,adaptOpenVPNTemplate};
