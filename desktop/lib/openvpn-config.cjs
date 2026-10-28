'use strict';
const {isIP}=require('node:net');
const MAX_OPENVPN_BYTES=256*1024;
const isOpenVPNConfig=text=>typeof text==='string'&&/^\s*(?:client|dev\s+tun|<ca>)\s*(?:[#;].*)?$/im.test(text);
const ciphers=new Set(['AES-128-GCM','AES-192-GCM','AES-256-GCM','AES-128-CBC','AES-192-CBC','AES-256-CBC','CHACHA20-POLY1305']);
function fail(message){throw new Error(`OpenVPN: ${message}`);}
function tokens(line){
  const values=[];let word='',quote='',escaped=false,active=false;
  for(const char of line){
    if(escaped){word+=char;escaped=false;active=true;continue;}
    if(char==='\\'&&quote==='"'){escaped=true;continue;}
    if(quote){if(char===quote)quote='';else word+=char;active=true;continue;}
    if(char==='"'||char==="'"){quote=char;active=true;continue;}
    if(char==='#'||char===';')break;
    if(/\s/.test(char)){if(active){values.push(word);word='';active=false;}}else{word+=char;active=true;}
  }
  if(quote||escaped)fail('Unterminated quoted field');if(active)values.push(word);return values;
}
function integer(value,label,min,max){if(!/^\d+$/.test(value||'')||!Number.isSafeInteger(+value)||+value<min||+value>max)fail(`Invalid ${label}`);return +value;}
function hostname(value){
  const host=String(value||'').replace(/^\[|\]$/g,'');
  if(!host||host.includes('%')||(!isIP(host)&&!(/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$/i).test(host)))fail('Invalid remote hostname');
  return host;
}
function proto(value){const p=String(value||'udp').toLowerCase();if(['udp','udp4'].includes(p))return 'udp';if(['tcp','tcp-client','tcp4','tcp4-client'].includes(p))return 'tcp';fail('Only OpenVPN UDP and TCP client profiles are supported');}
function credentials(value={}){
  const username=value.username,password=value.password;
  for(const [label,item]of [['username',username],['password',password]])if(typeof item!=='string'||!item||item.length>512||/[\x00-\x1f\x7f]/.test(item))fail(`A valid configuration ${label} is required`);
  return {username,password};
}
function validateOpenVPNNode(p){
  hostname(p.server);integer(String(p.port),'remote port',1,65535);p.proto=proto(p.proto);
  if(typeof p.ca!=='string'||p.ca.length>MAX_OPENVPN_BYTES||!p.ca.includes('-----BEGIN CERTIFICATE-----'))fail('An inline CA certificate is required');
  if(p.cert||p.key){if(typeof p.cert!=='string'||!p.cert.includes('-----BEGIN CERTIFICATE-----')||typeof p.key!=='string'||!p.key.includes('PRIVATE KEY-----')||/ENCRYPTED/.test(p.key))fail('A matching unencrypted inline client certificate/key is required');}
  else Object.assign(p,credentials(p));
  if(p.cipher&&!ciphers.has(String(p.cipher).toUpperCase()))fail('Unsupported data cipher');
  if(p['data-ciphers']&&(!Array.isArray(p['data-ciphers'])||p['data-ciphers'].some(x=>typeof x!=='string'||!ciphers.has(x.toUpperCase()))))fail('Unsupported data cipher list');
  if(p['verify-x509-name']&&(typeof p['verify-x509-name']!=='string'||p['verify-x509-name'].length>256||/[\x00-\x1f]/.test(p['verify-x509-name'])||!['name','name-prefix'].includes(p['verify-x509-name-type'])))fail('Unsupported certificate identity constraint');
  if(p['windscribe-mode']&&!['udp','tcp','stealth','wstunnel'].includes(p['windscribe-mode']))fail('Invalid Windscribe OpenVPN mode');
  return p;
}
function parseOpenVPNConfig(text,{name='OpenVPN',auth}={}){
  if(typeof text!=='string'||Buffer.byteLength(text)>MAX_OPENVPN_BYTES)fail('Configuration must be at most 256 KiB');
  if(typeof name!=='string'||!name.trim()||name.length>160||/[\x00-\x1f]/.test(name))fail('Invalid profile name');
  const fields=new Map(),blocks=new Map(),remotes=[],warnings=[];let block=null,contents=[];
  const ignored=new Set(['client','tls-client','pull','nobind','persist-key','persist-tun','auth-nocache','resolv-retry','connect-retry','connect-retry-max','connect-timeout','server-poll-timeout','verb','mute','mute-replay-warnings','route-delay','route-method','fast-io','mssfix','remote-random','explicit-exit-notify','sndbuf','rcvbuf','tls-exit']);
  const scalar=new Set(['dev','proto','port','cipher','data-ciphers','data-ciphers-fallback','auth','comp-lzo','key-direction','ping','ping-restart','tran-window','hand-window','tun-mtu','remote-cert-tls','verify-x509-name','auth-user-pass','reneg-sec','tls-version-min','dhcp-option','block-outside-dns']);
  for(const [index,raw]of text.replace(/^\uFEFF/,'').split(/\r?\n/).entries()){
    const line=raw.trim();
    if(block){if(line===`</${block}>`){blocks.set(block,contents.join('\n')+'\n');block=null;contents=[];}else contents.push(raw);continue;}
    const opening=/^<([a-z0-9-]+)>$/i.exec(line);
    if(opening){block=opening[1].toLowerCase();if(!['ca','cert','key','tls-auth','tls-crypt','tls-crypt-v2'].includes(block)||blocks.has(block))fail(`Unsupported or duplicate inline block at line ${index+1}`);continue;}
    const args=tokens(line);if(!args.length)continue;
    let directive=args.shift().toLowerCase();
    if(directive==='setenv'&&args.length===2&&args[0]==='CLIENT_CERT'&&args[1]==='0')continue;
    if(directive==='ncp-ciphers')directive='data-ciphers';
    if(directive==='remote'){if(args.length<1||args.length>3)fail(`Invalid remote at line ${index+1}`);remotes.push(args);continue;}
    if(['route','route-ipv6','redirect-gateway','redirect-ipv6'].includes(directive)){if(!warnings.includes('Profile OS routes are not imported; the desktop routing mode controls system traffic.'))warnings.push('Profile OS routes are not imported; the desktop routing mode controls system traffic.');continue;}
    if(ignored.has(directive))continue;
    if(!scalar.has(directive))fail(`Unsupported directive at line ${index+1}`);
    if(fields.has(directive)&&directive!=='dhcp-option')fail(`Duplicate directive at line ${index+1}`);
    if(directive==='dhcp-option'){const existing=fields.get(directive)||[];fields.set(directive,[...existing,args]);}else fields.set(directive,args);
  }
  if(block)fail('Unterminated inline block');if(!remotes.length||remotes.length>64)fail('One to 64 remote endpoints are required');
  const one=(field,optional=false)=>{const v=fields.get(field);if(!v)return undefined;if(v.length!==1){if(optional&&v.length===0)return '';fail(`Invalid ${field}`);}return v[0];};
  if(fields.has('dev')&&one('dev')!=='tun')fail('Only dev tun is supported');
  if(fields.has('remote-cert-tls')&&one('remote-cert-tls')!=='server')fail('Server certificate validation is required');
  if(fields.has('auth-user-pass')&&fields.get('auth-user-pass').length)fail('External credential files are not read; enter configuration credentials in the app');
  if(fields.has('reneg-sec')&&one('reneg-sec')!=='0')fail('Client-initiated renegotiation is not supported');
  if(fields.has('tls-version-min')&&!['1.0','1.1','1.2'].includes(one('tls-version-min')))fail('Unsupported minimum TLS version');
  const base={type:'openvpn',dev:'tun',udp:true,ca:blocks.get('ca')||'', 'handshake-timeout':20};
  for(const field of ['cert','key','tls-auth','tls-crypt','tls-crypt-v2'])if(blocks.has(field))base[field]=blocks.get(field);
  if(!(base.cert&&base.key))Object.assign(base,credentials(auth));
  for(const field of ['cipher','data-ciphers-fallback','auth','key-direction'])if(fields.has(field))base[field]=one(field).toUpperCase();
  if(fields.has('data-ciphers'))base['data-ciphers']=one('data-ciphers').split(':').map(x=>x.toUpperCase());
  if(fields.has('comp-lzo'))base['comp-lzo']=one('comp-lzo',true)||'adaptive';
  for(const [from,to,min,max]of [['ping','ping',0,3600],['ping-restart','ping-restart',0,3600],['tran-window','tran-window',0,3600],['hand-window','handshake-timeout',1,60],['tun-mtu','mtu',576,65535]])if(fields.has(from))base[to]=integer(one(from),from,min,max);
  if(fields.has('verify-x509-name')){const args=fields.get('verify-x509-name');if(args.length!==2||!['name','name-prefix'].includes(args[1]))fail('Certificate identity checks require name or name-prefix mode');base['verify-x509-name']=args[0];base['verify-x509-name-type']=args[1];}
  if(fields.has('dhcp-option')){const dns=[];for(const args of fields.get('dhcp-option')){if(args.length!==2||args[0]!=='DNS'||!isIP(args[1]))fail('Only IP-based dhcp-option DNS is supported');dns.push(args[1]);}if(dns.length){base.dns=[...new Set(dns)];base['remote-dns-resolve']=true;}}
  if(fields.has('block-outside-dns'))warnings.push('block-outside-dns is not imported as an OS firewall rule; DNS follows the desktop client settings.');
  const defaultPort=fields.has('port')?integer(one('port'),'port',1,65535):1194;
  const defaultProto=proto(one('proto'));
  const proxies=remotes.map((args,index)=>validateOpenVPNNode({...structuredClone(base),name:remotes.length===1?name.trim():`${name.trim()} #${index+1}`,server:hostname(args[0]),port:args[1]?integer(args[1],'remote port',1,65535):defaultPort,proto:args[2]?proto(args[2]):defaultProto}));
  return {proxies,warnings};
}
module.exports={parseOpenVPNConfig,validateOpenVPNNode,isOpenVPNConfig,MAX_OPENVPN_BYTES};
