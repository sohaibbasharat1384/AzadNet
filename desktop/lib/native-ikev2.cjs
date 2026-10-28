'use strict';
const fs=require('node:fs/promises');
const path=require('node:path');
const crypto=require('node:crypto');
const {spawn}=require('node:child_process');
const ownName=/^AzadNet-Windscribe-[a-f0-9]{32}$/;
function validateIKEv2Profile(p){
  if(typeof p.server!=='string'||!(/^(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/i).test(p.server))throw new Error('IKEv2 requires the server hostname from the configuration generator');
  for(const field of ['username','password'])if(typeof p[field]!=='string'||!p[field]||p[field].length>256||/[\x00-\x1f\x7f]/.test(p[field]))throw new Error(`Invalid IKEv2 configuration ${field}`);
  if(p.port!==500)throw new Error('IKEv2 uses the system IKE/NAT-T ports');
  return p;
}
function runPrivate(command,args,input,{timeout=120000,spawnProcess=spawn}={}){
  return new Promise((resolve,reject)=>{
    const child=spawnProcess(command,args,{windowsHide:true,shell:false,stdio:['pipe','pipe','pipe']});
    let out='',settled=false;
    const finish=(error,result)=>{if(settled)return;settled=true;clearTimeout(timer);if(error){try{child.kill();}catch{}reject(error);}else resolve(result);};
    const timer=setTimeout(()=>finish(new Error('IKEv2 system operation timed out')),timeout);
    child.stdout.on('data',data=>{out+=data.toString('utf8');if(Buffer.byteLength(out)>65536)finish(new Error('Invalid IKEv2 helper response'));});
    child.stderr.resume();child.stdin.on('error',()=>{});
    child.once('error',()=>finish(new Error('IKEv2 system backend is unavailable')));
    child.once('close',code=>{
      if(code!==0){finish(new Error('IKEv2 system backend failed'));return;}
      try{const result=JSON.parse(out.replace(/^\uFEFF/,''));if(result.error)finish(new Error(`IKEv2 system operation failed${Number.isInteger(result.code)?` (${result.code})`:''}`));else finish(null,result);}catch{finish(new Error('Invalid IKEv2 helper response'));}
    });
    child.stdin.end(JSON.stringify(input));
  });
}
class NativeIKEv2{
  constructor({dataDir,platform=process.platform,run=runPrivate}={}){this.dataDir=dataDir;this.platform=platform;this.run=run;this.file=path.join(dataDir,'native-ikev2.json');this.active=false;this.owner=null;}
  async request(operation,owner,profile){
    if(!ownName.test(owner.name))throw new Error('Invalid app-owned IKEv2 identifier');
    const input={operation,...owner,...(profile?{server:profile.server}:{}),...(operation==='connect'&&profile?{username:profile.username,password:profile.password}:{})};
    if(this.platform==='win32'){
      const executable=path.join(process.env.SystemRoot||'C:\\Windows','System32','WindowsPowerShell','v1.0','powershell.exe');
      return this.run(executable,['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',path.join(__dirname,'../bridge/ikev2_windows.ps1')],input,{timeout:operation==='connect'?120000:25000});
    }
    if(this.platform==='linux')return this.run('/usr/bin/python3',[path.join(__dirname,'../bridge/ikev2_nm.py')],input,{timeout:operation==='connect'?110000:25000});
    throw new Error('IKEv2 integration is available on Windows and Ubuntu');
  }
  async available(){
    try{
      if(this.platform==='linux'){
        const candidates=['/usr/lib/ipsec/charon-nm','/usr/libexec/ipsec/charon-nm','/usr/lib/NetworkManager/VPN/nm-strongswan-service.name'];
        let found=false;for(const file of candidates)try{await fs.access(file);found=true;break;}catch{}
        if(!found)return false;
      }
      return (await this.request('available',{name:'AzadNet-Windscribe-'+'0'.repeat(32)})).available===true;
    }catch{return false;}
  }
  async readOwner(){
    if(this.owner)return this.owner;
    try{const stat=await fs.stat(this.file);if(stat.size>4096)throw new Error('Invalid IKEv2 ownership receipt');const value=JSON.parse(await fs.readFile(this.file,'utf8'));if(!ownName.test(value.name)||!(/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/).test(value.uuid)||value.name!=='AzadNet-Windscribe-'+value.uuid.replaceAll('-','')||value.platform!==this.platform)throw new Error('Invalid IKEv2 ownership receipt');this.owner={name:value.name,uuid:value.uuid,platform:value.platform};return this.owner;}catch(e){if(e.code==='ENOENT')return null;throw e;}
  }
  async start(profile){
    validateIKEv2Profile(profile);await this.stop();
    const id=crypto.randomUUID(),owner={name:'AzadNet-Windscribe-'+id.replaceAll('-',''),uuid:id,platform:this.platform};
    await fs.mkdir(this.dataDir,{recursive:true,mode:0o700});
    if(this.platform==='win32'){
      const created=await this.request('create',owner,profile);if(created.created!==true)throw new Error('IKEv2 profile could not be created');
    }
    this.owner=owner;
    try{
      await fs.writeFile(this.file,JSON.stringify(owner),{mode:0o600});
      const result=await this.request('connect',owner,profile);
      if(result.connected!==true)throw new Error('IKEv2 did not establish a system connection');
      this.active=true;return {connected:true};
    }catch(error){try{await this.stop();}catch{throw new Error('IKEv2 connection failed and its system profile could not be cleaned up');}throw error;}
  }
  async status(){const owner=await this.readOwner();if(!owner)return {connected:false};const result=await this.request('status',owner);this.active=result.connected===true;return {connected:this.active};}
  async stop(){
    const owner=await this.readOwner();if(!owner){this.active=false;return;}
    const result=await this.request('stop',owner);if(result.stopped!==true)throw new Error('The app-owned IKEv2 connection is still active');
    await fs.rm(this.file,{force:true});this.owner=null;this.active=false;
  }
}
module.exports={NativeIKEv2,validateIKEv2Profile,runPrivate};
