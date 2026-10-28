'use strict';
const net=require('node:net');
const {parseWireGuardConfig}=require('./wireguard-config.cjs');
const {parseOpenVPNConfig}=require('./openvpn-config.cjs');
const {validateIKEv2Profile}=require('./native-ikev2.cjs');
const PROTOCOLS=['wireguard','udp','tcp','ikev2','stealth','wstunnel'];
function label(value){
  if(typeof value!=='string')throw new Error('A Windscribe profile name is required');
  const name=value.split(/[\\/]/).pop().replace(/\.(?:conf|ovpn)$/i,'').trim();
  if(!name||name.length>120||/[\x00-\x1f\x7f\u202a-\u202e\u2066-\u2069]/.test(name))throw new Error('Invalid Windscribe profile name');
  return name;
}
function parseWindscribeImport(files,options={}){
  if(!options||typeof options!=='object'||!PROTOCOLS.includes(options.protocol))throw new Error('Select a Windscribe protocol');
  const protocol=options.protocol;
  if(protocol==='ikev2'){
    const name=label(options.name);
    const proxy=validateIKEv2Profile({name:`Windscribe · ${name}`,type:'ikev2',port:500,server:options.server,username:options.username,password:options.password});
    return [{label:name,protocol,proxies:[proxy],warnings:[]}];
  }
  if(!Array.isArray(files)||files.length<1||files.length>32)throw new Error('Select one to 32 configuration files');
  const used=new Set();
  return files.map(file=>{
    if(!file||typeof file!=='object')throw new Error('Invalid Windscribe configuration');
    const name=label(file.name),id=name.toLowerCase();if(used.has(id))throw new Error('Profile filenames in one import must be different');used.add(id);
    try{
      const parsed=protocol==='wireguard'?parseWireGuardConfig(file.text,{name:`Windscribe · ${name}`}):parseOpenVPNConfig(file.text,{name:`Windscribe · ${name}`,auth:{username:options.username,password:options.password}});
      for(const proxy of parsed.proxies){
        if(protocol==='udp'||protocol==='tcp'){if(proxy.proto!==protocol)throw new Error('The selected UDP/TCP mode does not match this OpenVPN file');}
        if(['stealth','wstunnel'].includes(protocol)){
          if(proxy.proto!=='tcp')throw new Error('Stealth and WStunnel require an OpenVPN TCP profile');
          const host=options.outerServer||proxy.server,port=options.outerPort??443,sni=options.outerSni||'';
          if(typeof host!=='string'||!host||host.length>253||/[\s/?#@%\x00-\x1f]/.test(host)||!Number.isInteger(port)||port<1||port>65535)throw new Error('Invalid outer tunnel endpoint');
          if(!net.isIP(host)&&!(/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/i).test(host))throw new Error('Invalid outer tunnel hostname');
          if(typeof sni!=='string'||sni.length>253||/[\s/:?#@%\x00-\x1f]/.test(sni))throw new Error('Invalid outer TLS server name');
          proxy['outer-server']=host;proxy['outer-port']=port;proxy['outer-sni']=sni;proxy['outer-padding']=options.outerPadding===true;
        }
        proxy['windscribe-mode']=protocol;
      }
      return {label:name,protocol,...parsed};
    }catch(error){throw new Error(`Windscribe «${name}»: ${error.message}`);}
  });
}
module.exports={PROTOCOLS,parseWindscribeImport};
