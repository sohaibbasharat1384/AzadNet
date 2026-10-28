'use strict';
const fs=require('node:fs/promises');
const path=require('node:path');
const crypto=require('node:crypto');
const https=require('node:https');
const VERSION=require('../../package.json').version;
// API compatibility reference, not this application's own version. Matches
// cmake/integrations/windscribe.cmake at Desktop-App c64bb6f46065a11a2bdbbfd880565e996ee57146.
const API_COMPAT_VERSION='2.25.5';
const ENDPOINTS=new Set(['AuthToken/login','Session','ServerCredentials']);
const INTERNAL_CODES=new Set(['network','response','redirect','local','input','vault','session','cancel']);
// Public protocol signature salt from Windscribe/wsnet 1.5.43 settings.h;
// this is not a user credential or a private developer API key.
const SIGNATURE_SALT='if_you_copy_this_you_might_die_a_painful_death';
// Public client authentication protocol: browser-extension/ws-api-client,
// getMandatoryParams.ts at ed83749ad1a4163f24e39572fc9597a4091a0ee7.
const CLIENT_AUTH_SALT='952b4412f002315aa50751032fcaab03';
const errors={701:'نشست Windscribe معتبر نیست؛ دوباره وارد شوید.',702:'نام کاربری یا رمز حساب Windscribe درست نیست.',703:'ورود به این حساب توسط Windscribe پذیرفته نشد.',706:'این حساب توسط Windscribe غیرفعال شده است.',707:'تعداد درخواست‌های ورود زیاد است؛ کمی بعد دوباره امتحان کنید.',708:'مهلت تأیید امنیتی تمام شد؛ ورود را دوباره شروع کنید.',1337:'Windscribe نسخهٔ قرارداد API این کلاینت را نپذیرفت؛ برنامه به به‌روزرسانی نیاز دارد (کد 1337).',1340:'کد دومرحله‌ای حساب را وارد کنید.',1341:'کد دومرحله‌ای درست نیست؛ کد تازه را وارد کنید.'};
class WindscribeError extends Error{
  constructor(code,message,details={}){
    const unknown=Number.isInteger(code)&&!errors[code];
    super(message||errors[code]||(unknown?`Windscribe درخواست را نپذیرفت (کد ${code}).`:'Windscribe درخواست را نپذیرفت.'));
    this.code=code;
    if(Number.isInteger(details.httpStatus))this.httpStatus=details.httpStatus;
  }
}
function apiRequest({method,endpoint,parameters={},token,signal,requestImpl=https.request}){
  if(!ENDPOINTS.has(endpoint)||!['GET','POST','DELETE'].includes(method))return Promise.reject(new Error('Invalid Windscribe API operation'));
  return new Promise((resolve,reject)=>{
    const url=new URL('https://api.windscribe.com/'+endpoint);
    const time=String(Math.round(Date.now()/1000));
    const params=new URLSearchParams(Object.entries({...parameters,platform:process.platform==='win32'?'windows':'linux',app_version:API_COMPAT_VERSION,time,client_auth_hash:crypto.createHash('md5').update(CLIENT_AUTH_SALT+time).digest('hex')}).filter(([,value])=>value!==''&&value!=null));
    if(method!=='POST')url.search=params.toString();
    const body=method==='POST'?params.toString():null;
    const request=requestImpl(url,{method,signal,headers:{'User-Agent':`AzadNet/${VERSION} (Windscribe API compatibility/${API_COMPAT_VERSION})`,'X-AzadNet-Version':VERSION,'Accept':'application/json',...(body?{'Content-Type':'application/x-www-form-urlencoded; charset=utf-8','Content-Length':Buffer.byteLength(body)}:{}),...(token?{Authorization:`Bearer ${token}`}:{})}},response=>{
      let bytes=0;const chunks=[];const failure=(code,message)=>new WindscribeError(code,message,{httpStatus:response.statusCode});
      response.on('data',data=>{bytes+=data.length;if(bytes>2*1024*1024){response.destroy();reject(failure('response','پاسخ Windscribe بیش از حد بزرگ است.'));return;}chunks.push(data);});
      response.on('error',()=>reject(failure('network','ارتباط با Windscribe کامل نشد؛ وضعیت اینترنت را بررسی کنید.')));
      response.on('end',()=>{
        if(response.statusCode>=300&&response.statusCode<400){reject(failure('redirect','آدرس API تغییر کرده است؛ ورود برای محافظت از اطلاعات حساب متوقف شد.'));return;}
        if(response.statusCode===429){reject(failure(707));return;}
        let value;try{value=JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{reject(failure('response','پاسخ معتبر از API Windscribe دریافت نشد.'));return;}
        if(!value||typeof value!=='object'||Array.isArray(value)){reject(failure('response','پاسخ API Windscribe معتبر نیست.'));return;}
        if(value.errorCode){reject(failure(Number(value.errorCode)));return;}
        if(response.statusCode<200||response.statusCode>=300){reject(failure(response.statusCode));return;}
        if(!value.data||typeof value.data!=='object'||Array.isArray(value.data)){reject(failure('response','اطلاعات پاسخ Windscribe کامل نیست.'));return;}
        resolve(value.data);
      });
    });
    request.setTimeout(25000,()=>request.destroy());
    request.on('error',()=>reject(new WindscribeError('network',signal?.aborted?'عملیات ورود لغو شد.':'ارتباط امن با Windscribe برقرار نشد؛ اینترنت یا مسیر VPN را بررسی کنید.')));
    request.end(body);
  });
}
function text(value,max){return typeof value==='string'&&value.length<=max&&!/[\x00-\x1f\x7f]/.test(value);}
function captchaPNG(value){
  if(typeof value!=='string')throw new WindscribeError('captcha','تصویر CAPTCHA معتبر دریافت نشد.');
  const encoded=value.replace(/^data:image\/png;base64,/,'');
  if(encoded.length>1400000||!(/^[A-Za-z0-9+/]+={0,2}$/).test(encoded))throw new WindscribeError('captcha','تصویر CAPTCHA معتبر دریافت نشد.');
  const bytes=Buffer.from(encoded,'base64');
  if(bytes.length<24||!bytes.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10]))||bytes.toString('ascii',12,16)!=='IHDR')throw new WindscribeError('captcha','تصویر CAPTCHA باید PNG باشد.');
  const width=bytes.readUInt32BE(16),height=bytes.readUInt32BE(20);
  if(width<1||height<1||width>2048||height>1024)throw new WindscribeError('captcha','اندازهٔ تصویر CAPTCHA معتبر نیست.');
  return {src:'data:image/png;base64,'+encoded,width,height};
}
function captchaData(value){
  if(!value||typeof value!=='object')throw new WindscribeError('captcha','CAPTCHA معتبر دریافت نشد.');
  if(Object.hasOwn(value,'ascii_art')){
    const art=value.ascii_art;if(typeof art!=='string'||!art||art.length>16384||/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(art))throw new WindscribeError('captcha','متن CAPTCHA معتبر نیست.');
    return {captchaType:'ascii',asciiArt:art,image:null};
  }
  const background=captchaPNG(value.background),piece=captchaPNG(value.slider),top=value.top;
  if(!Number.isInteger(top)||top<0||piece.width>background.width||top+piece.height>background.height)throw new WindscribeError('captcha','ابعاد قطعهٔ CAPTCHA معتبر نیست.');
  return {captchaType:'image',asciiArt:null,image:{background,piece,top}};
}
function sessionProfile(data){
  if(!text(data.username,256)||!data.username||!text(data.user_id,256)||!data.user_id||!Number.isInteger(data.status)||![0,1].includes(data.is_premium))throw new WindscribeError('response','اطلاعات حساب Windscribe کامل نیست.');
  const number=n=>Number.isSafeInteger(n)&&n>=0?n:null;
  return {username:data.username,isPremium:data.is_premium===1,status:data.status,trafficUsed:number(data.traffic_used),trafficMax:number(data.traffic_max),unlimited:data.traffic_max===-1,expiresAt:text(data.premium_expiry_date,80)?data.premium_expiry_date:null};
}
class WindscribeAccount{
  constructor({dataDir,vault,request=apiRequest,emit=()=>{},onForget=async()=>{},now=Date.now}={}){
    this.file=path.join(dataDir,'windscribe-account.bin');this.vault=vault;this.request=request;this.emit=emit;this.onForget=onForget;this.now=now;
    this.token=null;this.identity=null;this.profile=null;this.pending=null;this.pendingTimer=null;this.busy=false;this.initializing=false;this.remembered=false;this.error=null;this.lastAttempt=-Infinity;this.abort=null;this.diagnostics=[];
  }
  canRemember(){try{return this.vault?.available()===true;}catch{return false;}}
  state(){const p=this.pending;return {loggedIn:!!(this.token&&this.profile),restoring:!!(this.token&&!this.profile),busy:this.busy||this.initializing,remembered:this.remembered,canRemember:this.canRemember(),profile:this.profile?{...this.profile}:null,error:this.error,challenge:p?{id:p.id,phase:p.phase,captchaType:p.captchaType||p.preference||'image',asciiArt:p.phase==='captcha'?p.asciiArt:null,image:p.phase==='captcha'&&p.image?structuredClone(p.image):null,message:p.message,expiresAt:p.expiresAt}:null};}
  publish(){this.emit(this.state());}
  clearPending(){clearTimeout(this.pendingTimer);this.pendingTimer=null;this.pending=null;}
  cancel(){this.abort?.abort();this.clearPending();this.error=null;this.publish();return this.state();}
  async operation(fn){
    if(this.busy||this.initializing)throw new Error('عملیات حساب Windscribe در حال انجام است.');
    this.busy=true;this.error=null;this.abort=new AbortController();this.publish();
    try{const result=await fn();return result&&Object.hasOwn(result,'loggedIn')?{...result,busy:false}:result;}catch(error){const safe=error instanceof WindscribeError?error:new WindscribeError('local','عملیات حساب Windscribe کامل نشد؛ دوباره تلاش کنید.');this.error=safe.message;throw safe;}
    finally{this.busy=false;this.abort=null;this.publish();}
  }
  async api(method,endpoint,parameters={},token=this.token){
    try{return await this.request({method,endpoint,parameters,token,signal:this.abort?.signal});}
    catch(error){
      const code=Number.isInteger(error.code)?error.code:INTERNAL_CODES.has(error.code)?error.code:'unknown';
      const status=Number.isInteger(error.httpStatus)?error.httpStatus:'unavailable';
      this.diagnostics.push({time:new Date(this.now()).toISOString(),message:`Windscribe account: ${method} ${ENDPOINTS.has(endpoint)?endpoint:'unknown'}; code=${code}; HTTP=${status}`});
      if(this.diagnostics.length>50)this.diagnostics.shift();throw error;
    }
  }
  getDiagnostics(){return this.diagnostics.map(entry=>({...entry}));}
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
      const attempt={id:crypto.randomBytes(24).toString('hex'),username:input.username.trim(),password:input.password,code2fa:code,remember:input.remember===true,preference:'image',phase:'preparing',expiresAt:this.now()+180000};
      this.pending=attempt;this.pendingTimer=setTimeout(()=>{this.clearPending();this.publish();},180000);this.pendingTimer.unref?.();
      try{return await this.prepare(attempt);}catch(error){this.clearPending();throw error;}
    });
  }
  checkAttempt(attempt){if(this.pending!==attempt||this.now()>attempt.expiresAt){this.clearPending();throw new WindscribeError(708);}if(this.abort?.signal.aborted)throw new WindscribeError('cancel','عملیات ورود لغو شد.');}
  async prepare(attempt){
    const auth=await this.api('POST','AuthToken/login',{username:attempt.username,...(attempt.preference==='ascii'?{captcha_type:'ascii'}:{})},null);this.checkAttempt(attempt);
    if(!text(auth.token,4096)||!auth.token)throw new WindscribeError('response','توکن امنیتی معتبر از Windscribe دریافت نشد.');
    attempt.secureToken=auth.token;
    if(auth.captcha){
      Object.assign(attempt,captchaData(auth.captcha));attempt.phase='captcha';attempt.message=attempt.captchaType==='image'?'دستهٔ زیر تصویر را خودتان حرکت دهید تا قطعه در جای مناسب قرار بگیرد؛ سپس «تأیید» را بزنید.':'متن CAPTCHA نمایش‌داده‌شده را خودتان وارد کنید.';return this.state();
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
      if(attempt.phase!=='captcha')throw new WindscribeError('input','ابتدا CAPTCHA تازه دریافت کنید.');
      let trails={};
      if(attempt.captchaType==='image'){
        const solution=input.captchaSolution,x=input.captchaTrailX,y=input.captchaTrailY;
        if(typeof solution!=='string'||!/^\d{1,4}$/.test(solution)||Number(solution)>attempt.image.background.width-attempt.image.piece.width||!Array.isArray(x)||!Array.isArray(y)||!x.length||x.length>50||x.length!==y.length||[...x,...y].some(n=>!Number.isFinite(n)||Math.abs(n)>16384))throw new WindscribeError('input','قطعه را با ماوس، لمس یا کلیدهای جهت‌نما تنظیم کنید.');
        trails={captchaTrailX:x,captchaTrailY:y};
      }else if(!text(input.captchaSolution,256)||!input.captchaSolution.trim())throw new WindscribeError('input','متن CAPTCHA را وارد کنید.');
      try{return await this.authenticate(attempt,input.captchaSolution.trim(),trails);}catch(error){this.clearPending();throw error;}
    });
  }
  async refreshCaptcha(input){return this.operation(async()=>{
    const attempt=this.pending;if(!attempt||input?.id!==attempt.id)throw new WindscribeError(708);this.checkAttempt(attempt);
    if(!['captcha','captcha-retry'].includes(attempt.phase)||!['image','ascii'].includes(input.type))throw new WindscribeError('input','نوع CAPTCHA را انتخاب کنید.');
    if(this.now()-this.lastAttempt<2000)throw new WindscribeError(707);this.lastAttempt=this.now();
    attempt.id=crypto.randomBytes(24).toString('hex');attempt.preference=input.type;attempt.phase='preparing';attempt.image=null;attempt.asciiArt=null;
    try{return await this.prepare(attempt);}catch(error){this.clearPending();throw error;}
  });}
  async authenticate(attempt,solution,{captchaTrailX=[],captchaTrailY=[]}={}){
    let data;
    try{
      const trail={};for(let i=0;i<captchaTrailX.length;i++){trail[`captcha_trail[x][${i}]`]=captchaTrailX[i].toFixed(3);trail[`captcha_trail[y][${i}]`]=captchaTrailY[i].toFixed(3);}
      data=await this.api('POST','Session',{username:attempt.username,password:attempt.password,'2fa_code':attempt.code2fa,session_type_id:'3',secure_token:attempt.secureToken,secure_token_sig:crypto.createHash('sha256').update(attempt.secureToken+SIGNATURE_SALT).digest('hex'),captcha_solution:solution,...trail},null);
    }catch(error){
      this.checkAttempt(attempt);
      if([1340,1341].includes(error.code)){attempt.phase='2fa';attempt.secureToken=null;attempt.asciiArt=null;attempt.message=errors[error.code];return this.state();}
      if(error.code===708){attempt.phase='captcha-retry';attempt.secureToken=null;attempt.image=null;attempt.asciiArt=null;attempt.message='پاسخ CAPTCHA پذیرفته نشد یا اعتبار آن تمام شده است؛ با دکمهٔ «CAPTCHA تازه» دوباره امتحان کنید.';return this.state();}
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
module.exports={WindscribeAccount,WindscribeError,apiRequest,sessionProfile,captchaData};
