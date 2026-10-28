'use strict';
const fs=require('node:fs/promises');
const path=require('node:path');
const crypto=require('node:crypto');
const https=require('node:https');
const VERSION=require('../../package.json').version;
const ENDPOINTS=new Set(['AuthToken/login','Session','ServerCredentials']);
// Public protocol signature salt from Windscribe/wsnet 1.5.43 settings.h;
// this is not a user credential or a private developer API key.
const SIGNATURE_SALT='if_you_copy_this_you_might_die_a_painful_death';
// Public client authentication protocol: browser-extension/ws-api-client,
// getMandatoryParams.ts at ed83749ad1a4163f24e39572fc9597a4091a0ee7.
const CLIENT_AUTH_SALT='952b4412f002315aa50751032fcaab03';
const errors={701:'نشست Windscribe معتبر نیست؛ دوباره وارد شوید.',702:'نام کاربری یا رمز حساب Windscribe درست نیست.',703:'ورود به این حساب توسط Windscribe پذیرفته نشد.',706:'این حساب توسط Windscribe غیرفعال شده است.',707:'تعداد درخواست‌های ورود زیاد است؛ کمی بعد دوباره امتحان کنید.',708:'مهلت تأیید امنیتی تمام شد؛ ورود را دوباره شروع کنید.',1340:'کد دومرحله‌ای حساب را وارد کنید.',1341:'کد دومرحله‌ای درست نیست؛ کد تازه را وارد کنید.'};
class WindscribeError extends Error{constructor(code,message){super(message||errors[code]||'Windscribe درخواست را نپذیرفت.');this.code=code;}}
function apiRequest({method,endpoint,parameters={},token,signal,requestImpl=https.request}){
  if(!ENDPOINTS.has(endpoint)||!['GET','POST','DELETE'].includes(method))return Promise.reject(new Error('Invalid Windscribe API operation'));
  return new Promise((resolve,reject)=>{
    const url=new URL('https://api.windscribe.com/'+endpoint);
    const time=String(Math.round(Date.now()/1000));
    const params=new URLSearchParams(Object.entries({platform:process.platform==='win32'?'windows':'linux',app_version:VERSION,...parameters,time,client_auth_hash:crypto.createHash('md5').update(CLIENT_AUTH_SALT+time).digest('hex')}).filter(([,value])=>value!==''&&value!=null));
    if(method!=='POST')url.search=params.toString();
    const body=method==='POST'?params.toString():null;
    const request=requestImpl(url,{method,signal,headers:{'User-Agent':`AzadNet/${VERSION}`,'Accept':'application/json',...(body?{'Content-Type':'application/x-www-form-urlencoded; charset=utf-8','Content-Length':Buffer.byteLength(body)}:{}),...(token?{Authorization:`Bearer ${token}`}:{})}},response=>{
      let bytes=0;const chunks=[];
      response.on('data',data=>{bytes+=data.length;if(bytes>2*1024*1024){response.destroy();reject(new WindscribeError('response','پاسخ Windscribe بیش از حد بزرگ است.'));return;}chunks.push(data);});
      response.on('error',()=>reject(new WindscribeError('network','ارتباط با Windscribe کامل نشد؛ وضعیت اینترنت را بررسی کنید.')));
      response.on('end',()=>{
        if(response.statusCode>=300&&response.statusCode<400){reject(new WindscribeError('redirect','آدرس API تغییر کرده است؛ ورود برای محافظت از اطلاعات حساب متوقف شد.'));return;}
        if(response.statusCode===429){reject(new WindscribeError(707));return;}
        let value;try{value=JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{reject(new WindscribeError('response','پاسخ معتبر از API Windscribe دریافت نشد.'));return;}
        if(!value||typeof value!=='object'||Array.isArray(value)){reject(new WindscribeError('response','پاسخ API Windscribe معتبر نیست.'));return;}
        if(value.errorCode){reject(new WindscribeError(Number(value.errorCode)));return;}
        if(response.statusCode<200||response.statusCode>=300){reject(new WindscribeError(response.statusCode));return;}
        if(!value.data||typeof value.data!=='object'||Array.isArray(value.data)){reject(new WindscribeError('response','اطلاعات پاسخ Windscribe کامل نیست.'));return;}
        resolve(value.data);
      });
    });
    request.setTimeout(25000,()=>request.destroy());
    request.on('error',()=>reject(new WindscribeError('network',signal?.aborted?'عملیات ورود لغو شد.':'ارتباط امن با Windscribe برقرار نشد؛ اینترنت یا مسیر VPN را بررسی کنید.')));
    request.end(body);
  });
}
function text(value,max){return typeof value==='string'&&value.length<=max&&!/[\x00-\x1f\x7f]/.test(value);}
function sessionProfile(data){
  if(!text(data.username,256)||!data.username||!text(data.user_id,256)||!data.user_id||!Number.isInteger(data.status)||![0,1].includes(data.is_premium))throw new WindscribeError('response','اطلاعات حساب Windscribe کامل نیست.');
  const number=n=>Number.isSafeInteger(n)&&n>=0?n:null;
  return {username:data.username,isPremium:data.is_premium===1,status:data.status,trafficUsed:number(data.traffic_used),trafficMax:number(data.traffic_max),unlimited:data.traffic_max===-1,expiresAt:text(data.premium_expiry_date,80)?data.premium_expiry_date:null};
}
class WindscribeAccount{
  constructor({dataDir,vault,request=apiRequest,emit=()=>{},onForget=async()=>{},now=Date.now}={}){
    this.file=path.join(dataDir,'windscribe-account.bin');this.vault=vault;this.request=request;this.emit=emit;this.onForget=onForget;this.now=now;
    this.token=null;this.identity=null;this.profile=null;this.pending=null;this.pendingTimer=null;this.busy=false;this.initializing=false;this.remembered=false;this.error=null;this.lastAttempt=-Infinity;this.abort=null;
  }
  canRemember(){try{return this.vault?.available()===true;}catch{return false;}}
  state(){const p=this.pending;return {loggedIn:!!(this.token&&this.profile),restoring:!!(this.token&&!this.profile),busy:this.busy||this.initializing,remembered:this.remembered,canRemember:this.canRemember(),profile:this.profile?{...this.profile}:null,error:this.error,challenge:p?{id:p.id,phase:p.phase,asciiArt:p.phase==='captcha'?p.asciiArt:null,message:p.message,expiresAt:p.expiresAt}:null};}
  publish(){this.emit(this.state());}
  clearPending(){clearTimeout(this.pendingTimer);this.pendingTimer=null;this.pending=null;}
  cancel(){this.abort?.abort();this.clearPending();this.error=null;this.publish();return this.state();}
  async operation(fn){
    if(this.busy||this.initializing)throw new Error('عملیات حساب Windscribe در حال انجام است.');
    this.busy=true;this.error=null;this.abort=new AbortController();this.publish();
    try{const result=await fn();return result&&Object.hasOwn(result,'loggedIn')?{...result,busy:false}:result;}catch(error){const safe=error instanceof WindscribeError?error:new WindscribeError('local','عملیات حساب Windscribe کامل نشد؛ دوباره تلاش کنید.');this.error=safe.message;throw safe;}
    finally{this.busy=false;this.abort=null;this.publish();}
  }
  api(method,endpoint,parameters={},token=this.token){return this.request({method,endpoint,parameters,token,signal:this.abort?.signal});}
  async init(){
    if(!this.canRemember())return this.state();
    if(this.initializing||this.busy)return this.state();this.initializing=true;this.publish();
    try{
      const stat=await fs.stat(this.file);if(stat.size>65536)throw new Error('Invalid vault');
      const saved=JSON.parse(this.vault.decrypt(await fs.readFile(this.file)));
      if(saved.version!==1||!text(saved.token,4096)||!saved.token||!(/^[a-f0-9]{64}$/).test(saved.identity))throw new Error('Invalid vault');
      this.token=saved.token;this.identity=saved.identity;this.remembered=true;
    }catch(error){if(error.code!=='ENOENT')this.error='نشست ذخیره‌شده باز نشد؛ دوباره وارد Windscribe شوید.';return {...this.state(),busy:false};}
    finally{this.initializing=false;this.publish();}
    try{await this.refresh();}catch{}return this.state();
  }
  async save(){
    if(!this.remembered){await fs.rm(this.file,{force:true});return;}
    if(!this.canRemember())throw new WindscribeError('vault','ذخیرهٔ امن سیستم آماده نیست؛ بدون گزینهٔ «مرا به خاطر بسپار» وارد شوید.');
    const bytes=this.vault.encrypt(JSON.stringify({version:1,token:this.token,identity:this.identity}));
    await fs.mkdir(path.dirname(this.file),{recursive:true,mode:0o700});
    const temp=this.file+'.'+crypto.randomBytes(8).toString('hex')+'.tmp';
    try{await fs.writeFile(temp,bytes,{mode:0o600});await fs.rename(temp,this.file);}finally{await fs.rm(temp,{force:true});}
  }
  async begin(input){
    return this.operation(async()=>{
      if(this.token)throw new WindscribeError('session','ابتدا از حساب قبلی خارج شوید.');
      if(this.now()-this.lastAttempt<2000)throw new WindscribeError(707);
      if(!input||!text(input.username,256)||!input.username.trim()||!text(input.password,512)||!input.password)throw new WindscribeError('input','نام کاربری و رمز حساب را وارد کنید.');
      if(input.remember===true&&!this.canRemember())throw new WindscribeError('vault','ذخیرهٔ امن سیستم آماده نیست؛ گزینهٔ «مرا به خاطر بسپار» را خاموش کنید.');
      const code=input.code2fa||'';if(code&&!/^\d{6}$/.test(code))throw new WindscribeError('input','کد دومرحله‌ای باید شش رقم باشد.');
      this.lastAttempt=this.now();this.clearPending();
      const attempt={id:crypto.randomBytes(24).toString('hex'),username:input.username.trim(),password:input.password,code2fa:code,remember:input.remember===true,phase:'preparing',expiresAt:this.now()+180000};
      this.pending=attempt;this.pendingTimer=setTimeout(()=>{this.clearPending();this.publish();},180000);this.pendingTimer.unref?.();
      try{return await this.prepare(attempt);}catch(error){this.clearPending();throw error;}
    });
  }
  checkAttempt(attempt){if(this.pending!==attempt||this.now()>attempt.expiresAt){this.clearPending();throw new WindscribeError(708);}if(this.abort?.signal.aborted)throw new WindscribeError('cancel','عملیات ورود لغو شد.');}
  async prepare(attempt){
    const auth=await this.api('POST','AuthToken/login',{username:attempt.username,captcha_type:'ascii'},null);this.checkAttempt(attempt);
    if(!text(auth.token,4096)||!auth.token)throw new WindscribeError('response','توکن امنیتی معتبر از Windscribe دریافت نشد.');
    attempt.secureToken=auth.token;
    if(auth.captcha){
      const art=auth.captcha.ascii_art;if(typeof art!=='string'||!art||art.length>16384||/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(art))throw new WindscribeError('captcha','این نوع CAPTCHA پشتیبانی نمی‌شود؛ ورود را دوباره شروع کنید.');
      attempt.phase='captcha';attempt.asciiArt=art;attempt.message='متن CAPTCHA نمایش‌داده‌شده را خودتان وارد کنید.';return this.state();
    }
    return this.authenticate(attempt,'');
  }
  async continue(input){
    return this.operation(async()=>{
      const attempt=this.pending;if(!attempt||!input||input.id!==attempt.id)throw new WindscribeError(708);this.checkAttempt(attempt);
      if(this.now()-this.lastAttempt<1000)throw new WindscribeError(707);this.lastAttempt=this.now();
      if(attempt.phase==='2fa'){
        if(!/^\d{6}$/.test(input.code2fa||''))throw new WindscribeError('input','کد دومرحله‌ای شش‌رقمی را وارد کنید.');
        attempt.code2fa=input.code2fa;
        try{return await this.prepare(attempt);}catch(error){this.clearPending();throw error;}
      }
      if(attempt.phase!=='captcha'||!text(input.captchaSolution,256)||!input.captchaSolution.trim())throw new WindscribeError('input','متن CAPTCHA را وارد کنید.');
      try{return await this.authenticate(attempt,input.captchaSolution.trim());}catch(error){this.clearPending();throw error;}
    });
  }
  async authenticate(attempt,solution){
    let data;
    try{
      data=await this.api('POST','Session',{username:attempt.username,password:attempt.password,'2fa_code':attempt.code2fa,session_type_id:'3',secure_token:attempt.secureToken,secure_token_sig:crypto.createHash('sha256').update(attempt.secureToken+SIGNATURE_SALT).digest('hex'),captcha_solution:solution},null);
    }catch(error){
      this.checkAttempt(attempt);
      if([1340,1341].includes(error.code)){attempt.phase='2fa';attempt.secureToken=null;attempt.asciiArt=null;attempt.message=errors[error.code];return this.state();}
      throw error;
    }
    try{this.checkAttempt(attempt);}catch(error){if(text(data.session_auth_hash,4096)&&data.session_auth_hash)try{await this.request({method:'DELETE',endpoint:'Session',parameters:{},token:data.session_auth_hash});}catch{}throw error;}
    if(!text(data.session_auth_hash,4096)||!data.session_auth_hash)throw new WindscribeError('response','نشست معتبر از Windscribe دریافت نشد.');
    let profile;try{profile=sessionProfile(data);}catch(error){try{await this.request({method:'DELETE',endpoint:'Session',parameters:{},token:data.session_auth_hash});}catch{}throw error;}
    this.token=data.session_auth_hash;this.identity=crypto.createHash('sha256').update(data.user_id).digest('hex');this.profile=profile;this.remembered=attempt.remember;this.clearPending();
    try{await this.save();}catch{this.remembered=false;try{await fs.rm(this.file,{force:true});}catch{}this.error='ورود انجام شد، اما نشست ذخیره نشد؛ پس از بستن برنامه دوباره وارد شوید.';}
    return this.state();
  }
  async refresh(){return this.operation(async()=>{
    if(!this.token)return this.state();
    try{
      const data=await this.api('GET','Session');const profile=sessionProfile(data);
      const identity=crypto.createHash('sha256').update(data.user_id).digest('hex');if(identity!==this.identity)throw new WindscribeError(701);
      this.profile=profile;return this.state();
    }catch(error){if(error.code===701||error.code===706)await this.forget();throw error;}
  });}
  async credentials(protocol){return this.operation(async()=>{
    if(!this.token||!this.profile)throw new WindscribeError(701);
    if(!['ikev2','udp','tcp','stealth','wstunnel'].includes(protocol))throw new WindscribeError('input','WireGuard از کلید داخل فایل کانفیگ استفاده می‌کند.');
    let data;try{data=await this.api('GET','ServerCredentials',{type:protocol==='ikev2'?'ikev2':'openvpn'});}catch(error){if(error.code===701||error.code===706)await this.forget();throw error;}
    const result={};for(const field of ['username','password']){
      const value=data[field];if(typeof value!=='string'||value.length>2048||!(/^[A-Za-z0-9+/]+={0,2}$/).test(value))throw new WindscribeError('response','مشخصات اتصال معتبر از Windscribe دریافت نشد.');
      const decoded=Buffer.from(value,'base64').toString('utf8');if(!decoded||!text(decoded,512))throw new WindscribeError('response','مشخصات اتصال معتبر از Windscribe دریافت نشد.');result[field]=decoded;
    }
    return {...result,accountId:this.identity};
  });}
  async forget(){
    if(this.identity)await this.onForget(this.identity);
    await fs.rm(this.file,{force:true});this.token=null;this.identity=null;this.profile=null;this.remembered=false;this.clearPending();
  }
  async logout(){return this.operation(async()=>{
    const token=this.token;if(this.identity)await this.onForget(this.identity);
    let remoteRevoked=true;if(token)try{await this.api('DELETE','Session',{},token);}catch{remoteRevoked=false;}
    await fs.rm(this.file,{force:true});this.token=null;this.identity=null;this.profile=null;this.remembered=false;this.clearPending();
    if(!remoteRevoked)this.error='خروج محلی انجام شد؛ ابطال نشست در سرور تأیید نشد. از بخش My Account سایت می‌توانید نشست‌ها را حذف کنید.';
    return {...this.state(),remoteRevoked};
  });}
  shutdown(){this.abort?.abort();this.clearPending();this.token=null;this.profile=null;}
}
module.exports={WindscribeAccount,WindscribeError,apiRequest,sessionProfile};
