'use strict';
// Import mappings follow WhiteDNS/WhiteVPN-Desktop's mihomoconf links.go and
// xrayjson.go. This module converts server entries, never executes profile code.
const { isIP } = require('node:net');
const MAX_TEXT = 8 * 1024 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const object = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const csv = v => String(v || '').split(',').map(s => s.trim()).filter(Boolean);
const value = (q,...keys) => keys.map(k => q.get(k)).find(v => v && v.trim())?.trim() || '';
function num(v, label, min, max) {
  if ((typeof v !== 'number' && typeof v !== 'string') || String(v).trim() === '') throw new Error(`${label} is missing`);
  const n = Number(v);
  if (!Number.isSafeInteger(n) || n < min || n > max) throw new Error(`Invalid ${label}`);
  return n;
}
function nonempty(v,label) {
  if (typeof v !== 'string' || !v.trim() || /[\x00-\x1f\x7f]/.test(v)) throw new Error(`Invalid ${label}`);
  return v;
}
function address(v,label='server address') {
  const s = nonempty(v,label);
  if (/[\s/@?#]/.test(s)) throw new Error(`Invalid ${label}`);
  return s.replace(/^\[|\]$/g,'');
}
function baseKey(v,label) {
  const s = nonempty(v,label).replace(/-/g,'+').replace(/_/g,'/');
  if (!/^[A-Za-z0-9+/]{43}=?$/.test(s) || Buffer.from(s,'base64').length !== 32) throw new Error(`Invalid ${label}: expected a 32-byte Base64 key`);
  return Buffer.from(s,'base64').toString('base64');
}
function ipAddress(v) {
  const parts=String(v).trim().split('/'), family=isIP(parts[0]);
  if (!family || parts.length>2 || (parts[1]!==undefined && (!/^\d+$/.test(parts[1]) || +parts[1]>(family===4?32:128)))) throw new Error('Invalid WireGuard tunnel address');
  return {family,value:String(v).trim()};
}
function tunnelAddresses(p,entries,requireV4=false) {
  for (const v of entries) {
    const a=ipAddress(v), key=a.family===4?'ip':'ipv6';
    if (p[key] && p[key]!==a.value) throw new Error('Multiple WireGuard addresses of the same family are unsupported');
    p[key]=a.value;
  }
  if (!(requireV4?p.ip:p.ip||p.ipv6)) throw new Error('WireGuard tunnel address is missing');
}
function optionalInt(p,key,v,min=1,max=2147483647) { if(v!=='' && v!==undefined && v!==null) p[key]=num(v,key,min,max); }
function reserved(p,v,warnings) {
  if(v===undefined || v===null || v==='') return;
  const parts=Array.isArray(v)?v:csv(v);
  if(parts.length===3 && parts.every(n => (typeof n==='number'||/^\d+$/.test(n)) && Number.isInteger(+n) && +n>=0 && +n<=255)) p.reserved=parts.map(Number);
  else warnings.push('Malformed WireGuard reserved bytes were omitted (exactly three bytes are required)');
}
function name(v,fallback) { return nonempty(String(v||fallback).trim(),'server name').slice(0,180); }
function endpoint(raw) {
  // A custom scheme retains port 80/443, which HTTP URL normalization removes.
  const u=new URL(`wireguard://${raw}`);
  if(u.username||u.password||(u.pathname!==''&&u.pathname!=='/')||u.search||u.hash) throw new Error('Invalid WireGuard endpoint');
  return {server:address(u.hostname),port:num(u.port,'server port',1,65535)};
}
function noUnsafeTLS(settings,warnings) {
  if(settings?.allowInsecure===true || settings?.allowInsecure===1 || settings?.allowInsecure==='true' || settings?.allowInsecure==='1') warnings.push('Certificate verification remains enabled; imported allowInsecure was ignored');
}
function uriInput(text) {
  if(!/^(?:anytls|wg|wireguard):\/\//i.test(text) || /[\r\n]/.test(text)) return null;
  const u=new URL(text), q=u.searchParams, warnings=[];
  const p={name:name(decodeURIComponent(u.hash.slice(1)),u.hostname),type:u.protocol==='anytls:'?'anytls':'wireguard',server:address(u.hostname),port:num(u.port|| (u.protocol==='anytls:'?443:''),'server port',1,65535),udp:true};
  if(p.type==='anytls') {
    // Split encoded authority before decoding so a percent-encoded colon remains
    // part of a single password, while user:password selects the password half.
    const rawAuthority=text.slice(text.indexOf('://')+3).split(/[/?#]/)[0];
    const at=rawAuthority.lastIndexOf('@');
    if(at<0) throw new Error('AnyTLS password is missing');
    const raw=rawAuthority.slice(0,at), colon=raw.indexOf(':');
    p.password=nonempty(decodeURIComponent(colon<0?raw:raw.slice(colon+1)),'AnyTLS password');
    if(value(q,'sni','peer')) p.sni=value(q,'sni','peer');
    if(q.get('alpn')) p.alpn=csv(q.get('alpn'));
    if(q.get('fp')) p['client-fingerprint']=q.get('fp');
    if(q.get('hpkp')) p.fingerprint=q.get('hpkp');
    p['skip-cert-verify']=false;
    if(['1','true'].includes(value(q,'insecure','allowInsecure').toLowerCase())) warnings.push('Certificate verification remains enabled; imported insecure flag was ignored');
  } else {
    p['private-key']=baseKey(decodeURIComponent(u.username)+(u.password?`:${decodeURIComponent(u.password)}`:'')||value(q,'privatekey','private-key','private_key','secretkey'),'WireGuard private key');
    p['public-key']=baseKey(value(q,'publickey','public-key','public_key','peer_public_key','peerpublickey'),'WireGuard public key');
    tunnelAddresses(p,csv(value(q,'address','ip','addresses','local_address')));
    const psk=value(q,'presharedkey','pre-shared-key','pre_shared_key','psk');
    if(psk) p['pre-shared-key']=baseKey(psk,'WireGuard preshared key');
    const allowed=csv(value(q,'allowed_ips','allowedips','allowed-ips'));
    if(allowed.length) p['allowed-ips']=allowed.map(v=>ipAddress(v).value);
    optionalInt(p,'mtu',value(q,'mtu'),576,65535);
    optionalInt(p,'persistent-keepalive',value(q,'keepalive','persistent-keepalive','persistentkeepalive'),0,65535);
    reserved(p,q.get('reserved'),warnings);
  }
  return {proxies:[p],warnings};
}

const stringExtra={xPaddingBytes:'x-padding-bytes',xPaddingKey:'x-padding-key',xPaddingHeader:'x-padding-header',xPaddingPlacement:'x-padding-placement',xPaddingMethod:'x-padding-method',uplinkHttpMethod:'uplink-http-method',sessionPlacement:'session-placement',sessionKey:'session-key',seqPlacement:'seq-placement',seqKey:'seq-key',uplinkDataPlacement:'uplink-data-placement',uplinkDataKey:'uplink-data-key'};
const numberExtra={uplinkChunkSize:'uplink-chunk-size',scMaxEachPostBytes:'sc-max-each-post-bytes',scMinPostsIntervalMs:'sc-min-posts-interval-ms'};
const reuseExtra={maxConnections:'max-connections',maxConcurrency:'max-concurrency',cMaxReuseTimes:'c-max-reuse-times',hMaxRequestTimes:'h-max-request-times',hMaxReusableSecs:'h-max-reusable-secs'};
function headers(v) {
  if(!object(v)) throw new Error('Transport headers must be an object');
  const h={};
  for(const [key,val] of Object.entries(v)) {
    if(!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(key)||typeof val!=='string'||/[\r\n\0]/.test(val)) throw new Error('Invalid transport header');
    Object.defineProperty(h,key,{value:val,enumerable:true,writable:true,configurable:true});
  }
  return h;
}
function tls(p,security,s,warnings) {
  if(!security||security==='none') {p['skip-cert-verify']=false;return;}
  if(!['tls','reality'].includes(security)) throw new Error(`Unsupported stream security: ${security}`);
  s=s||{};p.tls=true;p['skip-cert-verify']=false;
  if(s.serverName) p[p.type==='trojan'?'sni':'servername']=nonempty(s.serverName,'TLS server name');
  if(s.fingerprint) p['client-fingerprint']=nonempty(s.fingerprint,'TLS fingerprint');
  if(s.alpn!==undefined) {if(!Array.isArray(s.alpn)||s.alpn.some(v=>typeof v!=='string'))throw new Error('Invalid TLS ALPN');p.alpn=[...s.alpn];}
  noUnsafeTLS(s,warnings);
  if(security==='reality') {
    p['reality-opts']={'public-key':nonempty(s.publicKey||s.password,'Reality public key')};
    if(s.shortId) {if(!/^(?:[0-9a-f]{2}){1,8}$/i.test(s.shortId)) throw new Error('Invalid Reality short ID');p['reality-opts']['short-id']=s.shortId;}
  }
  if(s.echConfigList||s.echForceQuery||s.certificates||s.pinnedPeerCertificateChainSha256) throw new Error('Unsupported TLS certificate/ECH settings; import native Mihomo YAML');
}
function applyExtra(target,extra,depth=0,warnings=[]) {
  if(!object(extra)||depth>3) throw new Error('Invalid or excessively nested XHTTP extra settings');
  const known=new Set([...Object.keys(stringExtra),...Object.keys(numberExtra),'noGRPCHeader','xPaddingObfsMode','xmux','downloadSettings']);
  for(const key of Object.keys(extra)) if(!known.has(key))throw new Error(`Unsupported XHTTP extra option: ${key}`);
  for(const [from,to] of Object.entries(stringExtra)) if(extra[from]!==undefined)target[to]=nonempty(extra[from],`XHTTP ${from}`);
  for(const [from,to] of Object.entries(numberExtra)) if(extra[from]!==undefined)target[to]=num(extra[from],`XHTTP ${from}`,0,2147483647);
  for(const [from,to] of [['noGRPCHeader','no-grpc-header'],['xPaddingObfsMode','x-padding-obfs-mode']])if(extra[from]!==undefined){if(typeof extra[from]!=='boolean')throw new Error(`Invalid XHTTP ${from}`);target[to]=extra[from];}
  if(extra.xmux!==undefined) {
    if(!object(extra.xmux))throw new Error('Invalid XHTTP xmux');
    const reuse={};
    for(const [key,v] of Object.entries(extra.xmux)) {
      if(key==='hKeepAlivePeriod')reuse['h-keep-alive-period']=num(v,key,0,2147483647);
      else if(reuseExtra[key]) {if(!/^[0-9]+(?:-[0-9]+)?$/.test(String(v)))throw new Error(`Invalid XHTTP ${key}`);reuse[reuseExtra[key]]=String(v);}
      else throw new Error(`Unsupported XHTTP xmux option: ${key}`);
    }
    target['reuse-settings']=reuse;
  }
  if(extra.downloadSettings!==undefined) {
    const d=extra.downloadSettings;
    if(!object(d))throw new Error('Invalid XHTTP download settings');
    const allowed=new Set(['address','port','security','tlsSettings','realitySettings','network','xhttpSettings']);
    for(const key of Object.keys(d))if(!allowed.has(key))throw new Error(`Unsupported XHTTP download option: ${key}`);
    if(d.network && !['xhttp','splithttp'].includes(d.network))throw new Error('XHTTP download transport must be xhttp');
    const output={};
    if(d.address)output.server=address(d.address,'XHTTP download server');
    if(d.port!==undefined)output.port=num(d.port,'XHTTP download port',1,65535);
    tls(output,d.security||'',d.security==='reality'?d.realitySettings:d.tlsSettings,warnings);
    if(d.xhttpSettings) {
      const x=d.xhttpSettings;
      if(!object(x))throw new Error('Invalid download xhttpSettings');
      for(const key of ['path','host','mode'])if(x[key])output[key]=nonempty(x[key],`XHTTP download ${key}`);
      if(x.headers)output.headers=headers(x.headers);
      const nested={...x};for(const key of ['path','host','mode','headers','extra'])delete nested[key];
      applyExtra(output,nested,depth+1,warnings);
      if(x.extra!==undefined)applyExtra(output,x.extra,depth+1,warnings);
    }
    target['download-settings']=output;
  }
}
function augmentTransport(p,q) {
  const network=(q.get('type')||q.get('network')||'tcp').toLowerCase();
  if(!['xhttp','splithttp','httpupgrade'].includes(network))return false;
  if(network==='httpupgrade') {
    p.network='httpupgrade';
    const opts={path:q.get('path')||'/',headers:{}};
    if(q.get('host'))opts.headers.Host=q.get('host');
    const ed=q.get('ed');
    if(ed!==null) {num(ed,'HTTP upgrade early data',0,2147483647);opts['v2ray-http-upgrade-fast-open']=true;}
    if(q.get('eh'))opts['early-data-header-name']=q.get('eh');
    if(/[\r\n\0]/.test(opts.path)||Object.values(opts.headers).some(v=>/[\r\n\0]/.test(v)))throw new Error('Invalid HTTP upgrade path or host');
    p['ws-opts']=opts;
  } else {
    p.network='xhttp';const opts={};
    for(const k of ['path','host','mode'])if(q.get(k))opts[k]=nonempty(q.get(k),`XHTTP ${k}`);
    if(opts.mode&&!['auto','packet-up','stream-up','stream-one'].includes(opts.mode))throw new Error('Unsupported XHTTP mode');
    if(q.has('extra')) {let e;try{e=JSON.parse(q.get('extra'));}catch{throw new Error('Invalid XHTTP extra JSON');}applyExtra(opts,e);}
    p['xhttp-opts']=opts;
  }
  return true;
}
function streamSettings(p,s,warnings) {
  if(s===undefined)return;
  if(!object(s))throw new Error('Invalid streamSettings');
  tls(p,s.security||'',s.security==='reality'?s.realitySettings:s.tlsSettings,warnings);
  if(s.sockopt?.dialerProxy || s.sockopt?.mark || s.sockopt?.interface)throw new Error('Unsupported Xray outbound socket dependency');
  const network=(s.network||'tcp').toLowerCase();
  if(network==='tcp'||network==='raw') {
    const tcp=s.tcpSettings||s.rawSettings;
    if(tcp?.header?.type && tcp.header.type!=='none')throw new Error('Unsupported Xray TCP header; import native Mihomo YAML');
    p.network='tcp';
  } else if(['ws','websocket','httpupgrade'].includes(network)) {
    p.network=network==='websocket'?'ws':network;
    const ws=network==='httpupgrade'?s.httpupgradeSettings:s.wsSettings;
    const opts={path:ws?.path?nonempty(ws.path,'WebSocket path'):'/'};
    if(ws?.headers)opts.headers=headers(ws.headers);
    if(ws?.host)opts.headers={...opts.headers,Host:nonempty(ws.host,'WebSocket host')};
    if(ws?.maxEarlyData!==undefined) {
      if(network==='httpupgrade')opts['v2ray-http-upgrade-fast-open']=num(ws.maxEarlyData,'early data',0,2147483647)>0;
      else opts['max-early-data']=num(ws.maxEarlyData,'early data',0,2147483647);
    }
    if(ws?.earlyDataHeaderName)opts['early-data-header-name']=nonempty(ws.earlyDataHeaderName,'early data header name');
    p['ws-opts']=opts;
  } else if(network==='grpc') {
    if(s.grpcSettings?.multiMode)throw new Error('Xray gRPC multiMode is unsupported');
    p.network='grpc';p['grpc-opts']={'grpc-service-name':s.grpcSettings?.serviceName?nonempty(s.grpcSettings.serviceName,'gRPC service name'):''};
  } else if(network==='h2'||network==='http') {
    const h=s.httpSettings||{};p.network='h2';p['h2-opts']={path:h.path?nonempty(h.path,'HTTP/2 path'):'/'};
    if(h.host!==undefined){if(!Array.isArray(h.host)||h.host.some(v=>typeof v!=='string'))throw new Error('Invalid HTTP/2 host list');p['h2-opts'].host=[...h.host];}
  } else if(network==='xhttp'||network==='splithttp') {
    const x=s.xhttpSettings||s.splithttpSettings||{};
    if(!object(x))throw new Error('Invalid XHTTP settings');
    const q=new URLSearchParams({type:network});for(const key of ['path','host','mode'])if(x[key])q.set(key,x[key]);
    augmentTransport(p,q);
    if(x.headers)p['xhttp-opts'].headers=headers(x.headers);
    if(x.extra)applyExtra(p['xhttp-opts'],x.extra,0,warnings);
  } else throw new Error(`Unsupported Xray transport: ${network}`);
}
function xrayProxy(o,warnings) {
  if(!object(o)||!object(o.settings))throw new Error('Invalid Xray outbound settings');
  if(o.proxySettings||o.sendThrough||o.mux?.enabled)throw new Error('Unsupported Xray outbound dependency or multiplexing');
  const kind=String(o.protocol||'').toLowerCase(),s=o.settings;
  const p={type:kind==='shadowsocks'?'ss':kind,udp:true,'skip-cert-verify':false};
  if(kind==='vless'||kind==='vmess') {
    if(!Array.isArray(s.vnext)||s.vnext.length!==1||!Array.isArray(s.vnext[0]?.users)||s.vnext[0].users.length!==1)throw new Error('Xray vnext requires exactly one server and user');
    const next=s.vnext[0],u=next.users[0];p.server=address(next.address);p.port=num(next.port,'server port',1,65535);
    if(!UUID.test(u.id||''))throw new Error('Invalid Xray UUID');p.uuid=u.id;
    if(kind==='vless'){if(u.flow)p.flow=u.flow.toLowerCase();if(u.encryption&&u.encryption!=='none')throw new Error('Unsupported VLESS encryption; import native Mihomo YAML');}
    else {p.alterId=num(u.alterId??0,'VMess alterId',0,65535);p.cipher=u.security||'auto';}
  } else if(kind==='trojan'||kind==='shadowsocks') {
    if(!Array.isArray(s.servers)||s.servers.length!==1)throw new Error('Xray server list requires exactly one server');
    const v=s.servers[0];p.server=address(v.address);p.port=num(v.port,'server port',1,65535);p.password=nonempty(v.password,'password');
    if(kind==='shadowsocks')p.cipher=nonempty(v.method,'Shadowsocks cipher');
  } else if(kind==='wireguard') {
    if(!Array.isArray(s.peers)||s.peers.length!==1)throw new Error('Xray WireGuard requires exactly one peer');
    const peer=s.peers[0];Object.assign(p,endpoint(peer.endpoint));delete p['skip-cert-verify'];
    p['private-key']=baseKey(s.secretKey,'WireGuard private key');p['public-key']=baseKey(peer.publicKey,'WireGuard public key');
    if(!Array.isArray(s.address))throw new Error('WireGuard tunnel address is missing');tunnelAddresses(p,s.address,true);
    if(peer.allowedIPs!==undefined){if(!Array.isArray(peer.allowedIPs))throw new Error('Invalid WireGuard allowed IPs');p['allowed-ips']=peer.allowedIPs.map(v=>ipAddress(v).value);}
    if(peer.preSharedKey)p['pre-shared-key']=baseKey(peer.preSharedKey,'WireGuard preshared key');
    optionalInt(p,'persistent-keepalive',peer.keepAlive,0,65535);optionalInt(p,'mtu',s.mtu,576,65535);reserved(p,s.reserved,warnings);
    if(o.streamSettings?.sockopt?.dialerProxy)throw new Error('Xray WireGuard chaining requires a native Mihomo profile');
    return p;
  } else throw new Error(`Unsupported Xray protocol: ${kind||'(missing)'}`);
  streamSettings(p,o.streamSettings,warnings);
  return p;
}
function parseExtraInput(text) {
  if(typeof text!=='string'||Buffer.byteLength(text)>MAX_TEXT)throw new Error('Subscription exceeds 8 MiB');
  text=text.replace(/^\uFEFF/,'').trim();
  const uri=uriInput(text);if(uri)return uri;
  if(!/^[{[]/.test(text))return null;
  let doc;try{doc=JSON.parse(text);}catch{return null;}
  const configs=Array.isArray(doc)?doc:[doc];
  if(!configs.some(c=>object(c)&&Array.isArray(c.outbounds)))return null;
  if(configs.length>10000)throw new Error('Too many Xray configurations');
  const proxies=[],warnings=[],names=new Set();
  for(const [ci,c] of configs.entries()) {
    if(!object(c)||!Array.isArray(c.outbounds)){warnings.push(`Configuration ${ci+1}: not an Xray configuration`);continue;}
    if(c.outbounds.length>10000)throw new Error('Too many Xray outbounds');
    if(c.inbounds||c.routing||c.dns||c.policy)warnings.push(`Configuration ${ci+1}: only server entries imported; Xray inbounds, routing, DNS and policy were omitted`);
    for(const [oi,o] of c.outbounds.entries()) {
      if(['freedom','blackhole','dns'].includes(o?.protocol))continue;
      try {
        if(proxies.length>=10000)throw new Error('Too many imported servers');
        const p=xrayProxy(o,warnings),base=name(c.remarks||o.tag,`${p.server}:${p.port}`);
        let n=base,suffix=2;while(names.has(n))n=`${base} (${suffix++})`;names.add(n);p.name=n;proxies.push(p);
      }catch(e){warnings.push(`Configuration ${ci+1}, outbound ${oi+1}: ${e.message}`);}
    }
  }
  if(!proxies.length)throw new Error(warnings.slice(0,5).join('; ')||'Xray configuration contains no supported proxy outbounds');
  return {proxies,warnings};
}
module.exports={parseExtraInput,augmentTransport};
