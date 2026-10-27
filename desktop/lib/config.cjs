'use strict';
const {ADVANCED_DEFAULTS,validateAdvanced,applyAdvanced}=require('./advanced.cjs');
const DEFAULT_SETTINGS={mixedPort:2080,controllerPort:9097,allowLan:false,tun:false,ipv6:false,dnsTransport:'doh',dnsServers:['https://1.1.1.1/dns-query','https://8.8.8.8/dns-query'],directDomains:[],mode:'rule',...ADVANCED_DEFAULTS};
function validateSettings(patch,current=DEFAULT_SETTINGS){
  if(!patch||typeof patch!=='object'||Array.isArray(patch))throw new Error('Settings must be an object');
  const advancedPatch=Object.fromEntries(Object.entries(patch).filter(([k])=>Object.hasOwn(ADVANCED_DEFAULTS,k)));
  const n={...current,...validateAdvanced(advancedPatch,current)};
  if(n.routingMode==='subscription')throw new Error('Subscription rules and groups are not reconstructed yet; select Iran or global routing');
  for(const [k,v]of Object.entries(patch)){
    if(Object.hasOwn(ADVANCED_DEFAULTS,k))continue;
    if(!(k in DEFAULT_SETTINGS))throw new Error(`Unknown setting: ${k}`);
    if(['mixedPort','controllerPort'].includes(k)){if(!Number.isInteger(v)||v<1024||v>65535)throw new Error('Local ports must be between 1024 and 65535');}
    else if(['allowLan','tun','ipv6'].includes(k)){if(typeof v!=='boolean')throw new Error(`${k} must be boolean`);}
    else if(k==='mode'){if(!['rule','global','direct'].includes(v))throw new Error('Invalid routing mode');}
    else if(k==='dnsTransport'){if(!['doh','dot'].includes(v))throw new Error('Invalid DNS transport');}
    else if(k==='dnsServers'){
      if(!Array.isArray(v)||v.length<1||v.length>10||v.some(s=>typeof s!=='string'||!(/^(https:\/\/|tls:\/\/)/.test(s))))throw new Error('Use HTTPS or TLS DNS server URLs');
      for(const s of v){let u;try{u=new URL(s);}catch{throw new Error('Invalid DNS URL');}if(!u.hostname||u.username||u.password)throw new Error('Invalid DNS URL');}
    }else if(k==='directDomains'){
      if(!Array.isArray(v)||v.length>1000||v.some(s=>typeof s!=='string'||!/^([a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(s)))throw new Error('Invalid direct domain');
    }
    n[k]=Array.isArray(v)?[...v]:v;
  }
  if(n.mixedPort===n.controllerPort)throw new Error('Proxy and controller ports must differ');
  if('dnsTransport'in patch&&!('dnsServers'in patch))n.dnsServers=n.dnsTransport==='dot'?['tls://1.1.1.1:853','tls://8.8.8.8:853']:[...DEFAULT_SETTINGS.dnsServers];
  return n;
}
function generateConfig(settings,proxies,secret,selected,opts={}){
  const names=proxies.map(p=>p.name);
  const order=selected&&names.includes(selected)?[selected,...names.filter(n=>n!==selected)]:names;
  const config={
    'mixed-port':settings.mixedPort,'allow-lan':settings.allowLan,'bind-address':settings.allowLan?'*':'127.0.0.1',mode:settings.mode,'log-level':'info',ipv6:settings.ipv6,'unified-delay':true,'tcp-concurrent':true,
    'external-controller':`127.0.0.1:${settings.controllerPort}`,secret,
    dns:{enable:true,ipv6:settings.ipv6,'enhanced-mode':'fake-ip','fake-ip-range':'198.18.0.1/16','default-nameserver':['1.1.1.1','8.8.8.8'],nameserver:[...settings.dnsServers],'proxy-server-nameserver':[...settings.dnsServers]},
    proxies,
    'proxy-groups':[{name:'AZADNET',type:'select',proxies:order.length?order:['DIRECT']}],
    rules:[...['127.0.0.0/8','10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','100.64.0.0/10'].map(ip=>`IP-CIDR,${ip},DIRECT,no-resolve`),...settings.directDomains.map(d=>`DOMAIN-SUFFIX,${d},DIRECT`),'MATCH,AZADNET'],
  };
  if(settings.tun)config.tun={enable:true,stack:'mixed','auto-route':true,'auto-detect-interface':true,'dns-hijack':['any:53'],'strict-route':true};
  return applyAdvanced(config,settings,opts);
}
module.exports={DEFAULT_SETTINGS,validateSettings,generateConfig};
