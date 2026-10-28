'use strict';
const { parse } = require('yaml');
const {parseExtraInput,augmentTransport}=require('./subscription-extra.cjs');
const {parseWireGuardConfig,isWireGuardConfig}=require('./wireguard-config.cjs');
const {validateOpenVPNNode,parseOpenVPNConfig,isOpenVPNConfig}=require('./openvpn-config.cjs');
const {validateIKEv2Profile}=require('./native-ikev2.cjs');
const SUPPORTED = new Set(['ss','ssr','vmess','vless','trojan','hysteria2','tuic','socks5','http','wireguard','openvpn','ikev2','ssh','direct','anytls']);
const MAX_TEXT = 8 * 1024 * 1024;
function decode64(text) {
  const s = text.replace(/\s/g,'').replace(/-/g,'+').replace(/_/g,'/');
  if (!s || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) throw new Error('Invalid Base64 data');
  return Buffer.from(s,'base64').toString('utf8');
}
function integer(value, fallback) {
  if (value === '' || value == null) { if (fallback !== undefined) return fallback; throw new Error('Port is missing'); }
  const n=Number(value); if (!Number.isInteger(n)||n<1||n>65535) throw new Error('Invalid server port'); return n;
}
function plain(value) { return value && typeof value==='object' && !Array.isArray(value); }
function transport(p,q) {
  const network=q.get('type')||q.get('network')||'tcp';
  if (!['tcp','ws','grpc','http','h2','httpupgrade','xhttp','splithttp'].includes(network)) throw new Error(`Unsupported transport: ${network}`);
  const augmented=augmentTransport(p,q);
  if (!augmented&&network!=='tcp') p.network=network;
  if(network==='ws') p['ws-opts']={path:q.get('path')||'/',headers:{Host:q.get('host')||p.server}};
  if(network==='grpc') p['grpc-opts']={'grpc-service-name':q.get('serviceName')||q.get('service_name')||''};
  if(network==='h2'||network==='http') p[`${network}-opts`]={path:q.get('path')||'/',host:(q.get('host')||p.server).split(',')};
  const security=q.get('security')||'';
  if(security==='tls'||security==='reality') p.tls=true;
  if(q.get('sni')||q.get('peer')||q.get('servername')) p.servername=q.get('sni')||q.get('peer')||q.get('servername');
  if(q.get('alpn')) p.alpn=q.get('alpn').split(',');
  if(q.get('fp')) p['client-fingerprint']=q.get('fp');
  if(q.get('flow')) p.flow=q.get('flow');
  if(security==='reality') {
    if(!q.get('pbk')) throw new Error('Reality public key is missing');
    p['reality-opts']={'public-key':q.get('pbk'),'short-id':q.get('sid')||''};
  }
  p['skip-cert-verify']=false;
}
function parseUri(line,index,warnings=[]) {
  const extra=parseExtraInput(line);
  if(extra){warnings.push(...extra.warnings);if(extra.proxies.length!==1)throw new Error('Expected one proxy URI');return validateProxy(extra.proxies[0],index);}
  if(line.startsWith('vmess://')) {
    const v=JSON.parse(decode64(line.slice(8)));
    const p={name:String(v.ps||`VMess ${index}`),type:'vmess',server:String(v.add||''),port:integer(v.port),uuid:v.id,alterId:Number(v.aid||0),cipher:v.scy||'auto',udp:true};
    const q=new URLSearchParams({type:v.net||'tcp',path:v.path||'/',host:v.host||'',security:v.tls==='tls'?'tls':'',sni:v.sni||'',alpn:v.alpn||'',fp:v.fp||''});
    transport(p,q); return validateProxy(p,index);
  }
  if(line.startsWith('ss://')) {
    let rest=line.slice(5),name=`Shadowsocks ${index}`;
    const hash=rest.indexOf('#'); if(hash>=0){name=decodeURIComponent(rest.slice(hash+1));rest=rest.slice(0,hash);}
    let query=''; const qi=rest.indexOf('?'); if(qi>=0){query=rest.slice(qi+1);rest=rest.slice(0,qi);}
    if(!rest.includes('@')) rest=decode64(rest);
    const at=rest.lastIndexOf('@'); if(at<0) throw new Error('Shadowsocks address is missing');
    let auth=rest.slice(0,at); if(!auth.includes(':')) auth=decode64(auth);
    const sep=auth.indexOf(':'); if(sep<0) throw new Error('Shadowsocks credentials are malformed');
    const u=new URL(`http://${rest.slice(at+1)}`);
    const p={name,type:'ss',server:u.hostname.replace(/^\[|\]$/g,''),port:integer(u.port),cipher:decodeURIComponent(auth.slice(0,sep)),password:decodeURIComponent(auth.slice(sep+1)),udp:true};
    const plugin=new URLSearchParams(query).get('plugin');
    if(plugin){const [kind,...opts]=plugin.split(';');p.plugin=kind; p['plugin-opts']={};for(const o of opts){const [k,...v]=o.split('=');p['plugin-opts'][k]=v.length?v.join('='):true;}}
    return validateProxy(p,index);
  }
  const u=new URL(line),protocol=u.protocol.slice(0,-1).toLowerCase();
  const type=({hy2:'hysteria2',socks:'socks5',https:'http'})[protocol]||protocol;
  if(!SUPPORTED.has(type)) throw new Error(`Unsupported protocol: ${protocol}`);
  const p={name:decodeURIComponent(u.hash.slice(1))||`${type.toUpperCase()} ${index}`,type,server:u.hostname.replace(/^\[|\]$/g,''),port:integer(u.port,({trojan:443,hysteria2:443,tuic:443,http:protocol==='https'?443:80,socks5:1080})[type]),udp:true};
  const user=decodeURIComponent(u.username),pass=decodeURIComponent(u.password),q=u.searchParams;
  if(type==='vless'){p.uuid=user;transport(p,q);}
  else if(type==='trojan'){p.password=user+(pass?`:${pass}`:'');transport(p,q);p.tls=true;}
  else if(type==='hysteria2'){p.password=user+(pass?`:${pass}`:'');p.sni=q.get('sni')||p.server;if(q.get('obfs')){p.obfs=q.get('obfs');p['obfs-password']=q.get('obfs-password')||'';}p['skip-cert-verify']=false;}
  else if(type==='tuic'){p.uuid=user;p.password=pass;p['congestion-controller']=q.get('congestion_control')||'cubic';p['udp-relay-mode']=q.get('udp_relay_mode')||'native';p.sni=q.get('sni')||p.server;p.alpn=(q.get('alpn')||'h3').split(',');p['skip-cert-verify']=false;}
  else if(type==='socks5'||type==='http'){if(user)p.username=user;if(pass)p.password=pass;if(protocol==='https')p.tls=true;}
  else throw new Error(`Import ${type} as Mihomo YAML`);
  return validateProxy(p,index);
}
function validateProxy(value,index) {
  if(!plain(value))throw new Error('Proxy must be an object');
  const p=JSON.parse(JSON.stringify(value));
  if(!SUPPORTED.has(p.type))throw new Error(`Unsupported proxy type: ${p.type}`);
  p.name=String(p.name||`Server ${index}`).trim().slice(0,180);
  if(!p.name||/[\x00-\x1f]/.test(p.name))throw new Error('Invalid server name');
  if(p.type!=='direct'){
    if(typeof p.server!=='string'||!p.server||/[\s\x00-\x1f]/.test(p.server))throw new Error('Invalid server address');
    p.port=integer(p.port);
  }
  if(['vmess','vless','tuic'].includes(p.type)&&!(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(p.uuid||'')))throw new Error('Invalid UUID');
  if(['trojan','ss','hysteria2','tuic','anytls'].includes(p.type)&&typeof p.password!=='string')throw new Error('Password is missing');
  if(p.type==='ss'&&!p.cipher)throw new Error('Shadowsocks cipher is missing');
  if(p.type==='openvpn')validateOpenVPNNode(p);
  if(p.type==='ikev2')validateIKEv2Profile(p);
  if(p['windscribe-mode']&&p.type==='wireguard'&&p['windscribe-mode']!=='wireguard')throw new Error('Invalid WireGuard transport mode');
  if(p['windscribe-mode']&&!['wireguard','openvpn','ikev2'].includes(p.type))throw new Error('Invalid Windscribe transport');
  if(Object.hasOwn(p,'skip-cert-verify')&&typeof p['skip-cert-verify']!=='boolean')throw new Error('skip-cert-verify must be boolean');
  if(!Object.hasOwn(p,'skip-cert-verify')&&['http','socks5','trojan','vmess','vless','hysteria2','tuic','anytls'].includes(p.type))p['skip-cert-verify']=false;
  return p;
}
function parseSubscription(text) {
  if(typeof text!=='string'||Buffer.byteLength(text)>MAX_TEXT)throw new Error('Subscription exceeds 8 MiB');
  text=text.replace(/^\uFEFF/,'').trim(); if(!text)throw new Error('Subscription is empty');
  if(isWireGuardConfig(text))return parseWireGuardConfig(text);
  if(isOpenVPNConfig(text))return parseOpenVPNConfig(text);
  const extra=parseExtraInput(text);if(extra){if(!extra.proxies.length)throw new Error(extra.warnings.join('; ')||'No supported proxies found');return {proxies:extra.proxies.map((p,i)=>validateProxy(p,i+1)),warnings:extra.warnings};}
  let raw;
  if(/^proxies\s*:/m.test(text)||/^(?:\{|\[|---)/.test(text)){
    let obj;try{obj=parse(text,{maxAliasCount:50,uniqueKeys:true});}catch(e){throw new Error(`Invalid YAML: ${e.message}`);}
    raw=Array.isArray(obj)?obj:obj?.proxies;
    if(!Array.isArray(raw))throw new Error('Mihomo YAML must contain a proxies array');
    if(!raw.length)throw new Error('Subscription contains no proxies');
    if(raw.length>10000)throw new Error('Subscription has too many proxies');
    const proxies=raw.map((p,i)=>validateProxy(p,i+1));return {proxies,warnings:!Array.isArray(obj)&&(obj.rules||obj['proxy-groups']||obj['proxy-providers']||obj['rule-providers'])?['Only server entries were imported; profile rules, groups and providers are not supported in this build']:[]};
  }
  if(!text.includes('://')){text=decode64(text).trim();if(!text.includes('://'))throw new Error('Unrecognized subscription format');}
  const proxies=[],warnings=[];
  for(const [i,line] of text.split(/\r?\n/).entries()){
    const s=line.trim();if(!s||s.startsWith('#'))continue;
    if(proxies.length>=10000)throw new Error('Subscription has too many proxies');
    try{proxies.push(parseUri(s,i+1,warnings));}catch(e){warnings.push(`Line ${i+1}: ${e.message}`);}
  }
  if(!proxies.length)throw new Error(warnings.slice(0,3).join('; ')||'No supported servers found');
  return {proxies,warnings};
}
module.exports={parseSubscription,parseUri,validateProxy,MAX_TEXT};
