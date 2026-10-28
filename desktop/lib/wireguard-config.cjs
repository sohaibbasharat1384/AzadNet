'use strict';
const {isIP}=require('node:net');
const MAX_WIREGUARD_BYTES=64*1024;
const isWireGuardConfig=text=>typeof text==='string'&&/^\s*\[(?:Interface|Peer)\]\s*(?:[#;].*)?$/im.test(text);
function fail(message){throw new Error(`WireGuard: ${message}`);}
function key(value,label){
  if(typeof value!=='string'||!(/^[A-Za-z0-9+/]{43}=?$/).test(value))fail(`${label} must be a 32-byte Base64 key`);
  const bytes=Buffer.from(value,'base64');
  if(bytes.length!==32)fail(`${label} must be a 32-byte Base64 key`);
  if(label!=='PresharedKey'&&bytes.every(x=>x===0))fail(`${label} cannot be an empty key`);
  return bytes.toString('base64');
}
function integer(value,label,min,max){
  if(!/^\d+$/.test(value||'')||!Number.isSafeInteger(+value)||+value<min||+value>max)fail(`Invalid ${label}`);
  return +value;
}
function cidr(value,label){
  const [address,bits,...rest]=value.split('/'),family=isIP(address);
  if(!family||address.includes('%')||rest.length||bits!==undefined&&(!/^\d+$/.test(bits)||+bits>(family===4?32:128)))fail(`Invalid ${label}`);
  return {family,value:`${address}/${bits===undefined?(family===4?32:128):+bits}`};
}
function endpoint(value){
  let match=/^\[([^\]]+)\]:(\d+)$/.exec(value||'');
  if(match){if(isIP(match[1])!==6||match[1].includes('%'))fail('Invalid IPv6 Endpoint');}
  else{
    match=/^([^\s:/?#@]+):(\d+)$/.exec(value||'');
    if(!match)fail('Endpoint must be hostname:port or [IPv6]:port');
    if(!isIP(match[1])&&!/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$/i.test(match[1]))fail('Invalid Endpoint hostname');
  }
  return {server:match[1],port:integer(match[2],'Endpoint port',1,65535)};
}
function parseWireGuardConfig(text,{name='WireGuard'}={}){
  if(typeof text!=='string'||Buffer.byteLength(text)>MAX_WIREGUARD_BYTES)fail('Configuration must be at most 64 KiB');
  if(typeof name!=='string'||!name.trim()||name.length>180||/[\x00-\x1f\x7f]/.test(name))fail('Invalid profile name');
  const sections={};let section;
  const lists=new Set(['address','dns','allowedips']);
  for(const [index,raw] of text.replace(/^\uFEFF/,'').split(/\r?\n/).entries()){
    const line=raw.replace(/[#;].*$/,'').trim();if(!line)continue;
    const header=/^\[([a-z]+)\]$/i.exec(line);
    if(header){
      section=header[1].toLowerCase();
      if(!['interface','peer'].includes(section)||sections[section])fail('Exactly one Interface and one Peer are supported');
      sections[section]=Object.create(null);continue;
    }
    const pair=/^([a-z][a-z0-9-]*)\s*=\s*(.*)$/i.exec(line);
    if(!section||!pair)fail(`Invalid syntax at line ${index+1}`);
    const field=pair[1].toLowerCase(),value=pair[2].trim();
    if(['preup','postup','predown','postdown'].includes(field))fail('Executable hooks are not supported');
    const allowed=section==='interface'?['privatekey','address','dns','mtu','listenport','table','saveconfig']:['publickey','presharedkey','endpoint','allowedips','persistentkeepalive'];
    if(!allowed.includes(field))fail(`Unsupported field at line ${index+1}`);
    if(!value)fail(`Empty field at line ${index+1}`);
    const fields=sections[section];
    if(Object.hasOwn(fields,field)&&!lists.has(field))fail(`Duplicate field at line ${index+1}`);
    fields[field]=Object.hasOwn(fields,field)?`${fields[field]},${value}`:value;
  }
  const iface=sections.interface,peer=sections.peer;
  if(!iface||!peer)fail('Interface and Peer sections are required');
  const warnings=[],proxy={name:name.trim(),type:'wireguard',...endpoint(peer.endpoint),'private-key':key(iface.privatekey,'PrivateKey'),'public-key':key(peer.publickey,'PublicKey'),udp:true};
  if(!iface.address)fail('Address is required');
  for(const item of new Set(iface.address.split(',').map(x=>x.trim()))){
    const addr=cidr(item,'Address'),field=addr.family===4?'ip':'ipv6';
    if(proxy[field]&&proxy[field]!==addr.value)fail('Multiple addresses of the same family cannot be represented');
    proxy[field]=addr.value;
  }
  if(!peer.allowedips)fail('AllowedIPs is required');
  proxy['allowed-ips']=[...new Set(peer.allowedips.split(',').map(x=>cidr(x.trim(),'AllowedIPs').value))];
  if(peer.presharedkey)proxy['pre-shared-key']=key(peer.presharedkey,'PresharedKey');
  if(peer.persistentkeepalive!==undefined)proxy['persistent-keepalive']=integer(peer.persistentkeepalive,'PersistentKeepalive',0,65535);
  if(iface.mtu!==undefined){proxy.mtu=integer(iface.mtu,'MTU',576,65535);if(proxy.ipv6&&proxy.mtu<1280)fail('IPv6 requires MTU of at least 1280');}
  if(iface.dns){
    const servers=[];let searches=false;
    for(const item of iface.dns.split(',').map(x=>x.trim())){
      if(isIP(item)&&!item.includes('%'))servers.push(item);
      else if(/^[a-z0-9.-]+$/i.test(item)&&item)searches=true;
      else fail('Invalid DNS entry');
    }
    if(servers.length){proxy.dns=[...new Set(servers)];proxy['remote-dns-resolve']=true;}
    if(searches)warnings.push('DNS search domains are not imported; DNS server addresses are preserved.');
  }
  if(iface.listenport!==undefined){integer(iface.listenport,'ListenPort',0,65535);warnings.push('ListenPort is managed by the desktop core.');}
  if(iface.table!==undefined&&iface.table.toLowerCase()!=='auto')fail('Custom routing Table is not supported');
  if(iface.saveconfig!==undefined&&iface.saveconfig.toLowerCase()!=='false')fail('SaveConfig cannot modify the original file');
  return {proxies:[proxy],warnings};
}
module.exports={parseWireGuardConfig,isWireGuardConfig,MAX_WIREGUARD_BYTES};
