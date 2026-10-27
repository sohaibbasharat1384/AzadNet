'use strict';
const path=require('node:path');
const fs=require('node:fs/promises');
const {spawn}=require('node:child_process');
function sanitizeLicense(status={}){
  const expiresAt=Number(status.expires_at)||0;
  return {available:true,active:status.active===true&&expiresAt*1000>Date.now(),reason:typeof status.reason==='string'?status.reason:null,planName:typeof status.plan_name==='string'?status.plan_name:'',daysLeft:Math.max(0,Math.ceil((expiresAt*1000-Date.now())/86400000)),expiresAt};
}
class OfficialLicense{
  constructor({platform=process.platform,root=path.join(process.env.ProgramFiles||'C:\\Program Files','InternetAzad369'),spawnProcess=spawn}={}){this.platform=platform;this.root=root;this.spawnProcess=spawnProcess;}
  async query(operation){
    if(this.platform!=='win32')return {license:{available:false,active:false,reason:'windows_only'}};
    const python=path.join(this.root,'runtime','python.exe'),checker=path.join(this.root,'license_core.py');
    try{await fs.access(python);await fs.access(checker);}catch{return {license:{available:false,active:false,reason:'official_app_missing'}};}
    const raw=await new Promise((resolve,reject)=>{
      const child=this.spawnProcess(python,['-B',path.join(__dirname,'..','bridge','official_license.py'),this.root,operation],{windowsHide:true,shell:false,stdio:['ignore','pipe','pipe']});
      let output='',settled=false;
      const finish=(error)=>{if(settled)return;settled=true;clearTimeout(timer);if(error){child.kill();reject(error);}else{try{resolve(JSON.parse(output));}catch{reject(new Error('پاسخ بررسی لایسنس نامعتبر است.'));}}};
      const timer=setTimeout(()=>finish(new Error('بررسی لایسنس نسخهٔ رسمی به پایان نرسید.')),15000);
      child.stdout.on('data',data=>{output+=data.toString('utf8');if(Buffer.byteLength(output)>10*1024*1024)finish(new Error('پاسخ نسخهٔ رسمی بیش از حد بزرگ است.'));});
      child.stderr.resume();child.once('error',()=>finish(new Error('اجرای بررسی لایسنس نسخهٔ رسمی ممکن نشد.')));child.once('exit',code=>finish(code===0?null:new Error('بررسی لایسنس نسخهٔ رسمی ناموفق بود.')));
    });
    if(raw.error==='official_checker_failed')throw new Error('بررسی لایسنس توسط برنامهٔ رسمی ناموفق بود.');
    const license=sanitizeLicense(raw.license);
    return {license,...(operation==='servers'?{configs:raw.configs,cachedAt:raw.cached_at,error:raw.error}:{})};
  }
  async status(){return (await this.query('status')).license;}
  async servers(){return this.query('servers');}
}
module.exports={OfficialLicense,sanitizeLicense};
