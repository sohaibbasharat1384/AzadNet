'use strict';
const crypto=require('node:crypto');
const {isIP}=require('node:net');
const {parseWireGuardConfig}=require('./wireguard-config.cjs');
const rawKey=value=>typeof value==='string'&&/^[A-Za-z0-9+/]{43}=$/.test(value)&&Buffer.from(value,'base64').length===32;
function publicFromPrivate(privateKey){
  const key=crypto.createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b656e04220420','hex'),Buffer.from(privateKey,'base64')]),format:'der',type:'pkcs8'});
  return crypto.createPublicKey(key).export({format:'der',type:'spki'}).subarray(-32).toString('base64');
}
function validateDevice(device){
  if(!device||typeof device!=='object'||!(/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/).test(device.id)||!rawKey(device.privateKey)||!rawKey(device.publicKey)||publicFromPrivate(device.privateKey)!==device.publicKey)throw new Error('Invalid saved Windscribe WireGuard device');
  return {id:device.id,privateKey:device.privateKey,publicKey:device.publicKey};
}
function createDevice(){
  const pair=crypto.generateKeyPairSync('x25519');
  return {id:crypto.randomUUID(),privateKey:pair.privateKey.export({format:'der',type:'pkcs8'}).subarray(-32).toString('base64'),publicKey:pair.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64')};
}
function hashedAddress(cidr,publicKey){
  if(typeof cidr!=='string')throw new Error('Windscribe did not return a WireGuard address range');
  const [address,bits,extra]=cidr.split('/'),family=isIP(address),prefix=Number(bits);
  if(extra||!bits||!Number.isInteger(prefix)||!family||prefix<0||prefix>(family===4?32:128))throw new Error('Invalid Windscribe WireGuard address range');
  const hash=crypto.createHash('sha256').update(Buffer.from(publicKey,'base64')).digest();
  if(family===4){
    const network=address.split('.').reduce((n,x)=>(n<<8n)|BigInt(x),0n),hostBits=32-prefix,mask=(1n<<BigInt(hostBits))-1n;
    const value=(network&~mask)|(BigInt(hash.readUInt32BE(0))&mask);
    return [24n,16n,8n,0n].map(n=>Number((value>>n)&255n)).join('.')+'/32';
  }
  if(address.includes('.'))throw new Error('Unsupported Windscribe IPv6 address range');
  const [left,right]=address.split('::'),a=left?left.split(':'):[],b=right?right.split(':'):[];
  const groups=address.includes('::')?[...a,...Array(8-a.length-b.length).fill('0'),...b]:a;
  if(groups.length!==8)throw new Error('Invalid Windscribe IPv6 address range');
  const network=groups.reduce((n,x)=>(n<<16n)|BigInt('0x'+x),0n),hostBits=128-prefix,mask=(1n<<BigInt(hostBits))-1n;
  const value=(network&~mask)|((BigInt('0x'+hash.toString('hex'))>>BigInt(256-hostBits))&mask);
  return Array.from({length:8},(_,i)=>((value>>BigInt((7-i)*16))&65535n).toString(16)).join(':')+'/128';
}
function wireguardProfile({device,config,peerKey,host,port,name,ipv6=false}){
  validateDevice(device);
  if(!config||!rawKey(config.PresharedKey)||!rawKey(peerKey))throw new Error('Windscribe returned an incomplete WireGuard key configuration');
  let address;
  if(Array.isArray(config.HashedCIDR)&&config.HashedCIDR.length)address=hashedAddress(config.HashedCIDR[0],device.publicKey);
  else if(typeof config.Address==='string')address=config.Address;
  else throw new Error('Windscribe did not return a WireGuard client address');
  let allowed=config.AllowedIPs;
  if(typeof allowed!=='string'||!allowed||/[\r\n]/.test(allowed))throw new Error('Windscribe did not return WireGuard routes');
  if(ipv6&&Array.isArray(config.HashedCIDRv6)&&config.HashedCIDRv6.length&&typeof config.AllowedIPsV6==='string'&&!/[\r\n]/.test(config.AllowedIPsV6)){
    address+=','+hashedAddress(config.HashedCIDRv6[0],device.publicKey);allowed+=','+config.AllowedIPsV6;
  }
  const text=`[Interface]\nPrivateKey=${device.privateKey}\nAddress=${address}\nDNS=10.255.255.1\nMTU=1280\n[Peer]\nPublicKey=${peerKey}\nPresharedKey=${config.PresharedKey}\nAllowedIPs=${allowed}\nEndpoint=${isIP(host)===6?'['+host+']':host}:${port}\nPersistentKeepalive=25\n`;
  return parseWireGuardConfig(text,{name}).proxies[0];
}
module.exports={createDevice,validateDevice,hashedAddress,wireguardProfile};
