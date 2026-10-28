'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const path=require('node:path');
const crypto=require('node:crypto');
const {EventEmitter}=require('node:events');
const {PassThrough}=require('node:stream');
const {WindscribeAccount,WindscribeError,apiRequest}=require('../desktop/lib/windscribe-account.cjs');
const accountPassword='fixture-account-password',token='fixture-session-token',connectionPassword='fixture-connection-password';
const profile={session_auth_hash:token,user_id:'fixture-user-id',username:'fixture-user',status:1,is_premium:1,traffic_used:1024,traffic_max:2048,premium_expiry_date:'2030-01-01'};
function vault(){const key=crypto.randomBytes(32);return {available:()=>true,encrypt(text){const iv=crypto.randomBytes(12),cipher=crypto.createCipheriv('aes-256-gcm',key,iv);return Buffer.concat([iv,cipher.update(text),cipher.final(),cipher.getAuthTag()]);},decrypt(bytes){const decipher=crypto.createDecipheriv('aes-256-gcm',key,bytes.subarray(0,12));decipher.setAuthTag(bytes.subarray(-16));return Buffer.concat([decipher.update(bytes.subarray(12,-16)),decipher.final()]).toString();}};}
async function fixture(handler,options={}){
  const root=path.resolve(__dirname,'../.tools/tmp');await fs.mkdir(root,{recursive:true});const dir=await fs.mkdtemp(path.join(root,'windscribe-account-'));
  let clock=100000;const calls=[],events=[],codec=options.vault||vault();
  const request=async value=>{calls.push({...value,parameters:{...value.parameters}});if(handler)return handler(value,calls);if(value.endpoint==='AuthToken/login')return {token:'fixture-security-token'};if(value.endpoint==='ServerCredentials')return {username:Buffer.from('fixture-config-user').toString('base64'),password:Buffer.from(connectionPassword).toString('base64')};return {...profile};};
  const account=new WindscribeAccount({dataDir:dir,vault:codec,request,now:()=>clock,emit:value=>events.push(value),...options});
  return {account,dir,root,calls,events,codec,request,advance(ms=2100){clock+=ms;},async login(remember=false){return account.begin({username:profile.username,password:accountPassword,remember});},async close(){account.shutdown();assert.ok(dir.startsWith(root+path.sep));await fs.rm(dir,{recursive:true,force:true});}};
}
test('direct login uses security preflight, desktop session and public signature; secrets never enter renderer state',async()=>{
  const f=await fixture();try{
    const result=await f.login();assert.equal(result.loggedIn,true);assert.equal(result.busy,false);assert.equal(f.calls.length,2);assert.equal(f.calls[0].endpoint,'AuthToken/login');assert.equal(f.calls[0].parameters.captcha_type,'ascii');
    const login=f.calls[1];assert.equal(login.parameters.password,accountPassword);assert.equal(login.parameters.session_type_id,'3');assert.equal(login.parameters.secure_token_sig,crypto.createHash('sha256').update('fixture-security-tokenif_you_copy_this_you_might_die_a_painful_death').digest('hex'));
    const publicState=JSON.stringify([result,f.events]);for(const secret of [accountPassword,token,'fixture-security-token','fixture-user-id'])assert.equal(publicState.includes(secret),false);await assert.rejects(fs.access(f.account.file),{code:'ENOENT'});
  }finally{await f.close();}
});
test('remember encrypts only the session and validates it on restart',async()=>{
  const f=await fixture();try{
    await f.login(true);const bytes=await fs.readFile(f.account.file);assert.equal(bytes.includes(Buffer.from(token)),false);assert.equal(bytes.includes(Buffer.from(accountPassword)),false);
    const plaintext=f.codec.decrypt(bytes);assert.equal(plaintext.includes(accountPassword),false);assert.deepEqual(Object.keys(JSON.parse(plaintext)).sort(),['identity','token','version']);
    const restored=new WindscribeAccount({dataDir:f.dir,vault:f.codec,request:f.request});await restored.init();assert.equal(restored.state().loggedIn,true);assert.equal(f.calls.at(-1).method,'GET');assert.equal(f.calls.at(-1).token,token);restored.shutdown();
  }finally{await f.close();}
});
test('CAPTCHA requires a human answer and 2FA continues with a fresh preflight without returning the password',async()=>{
  let logins=0,preflights=0;
  const f=await fixture(async request=>{
    if(request.endpoint==='AuthToken/login'){preflights++;return preflights===1?{token:'first-security-token',captcha:{ascii_art:'A B C\nD E F'}}:{token:'second-security-token'};}
    if(request.method==='POST'){if(++logins===1)throw new WindscribeError(1340);assert.equal(request.parameters['2fa_code'],'123456');return {...profile};}
  });try{
    const start=await f.login();assert.equal(logins,0);assert.equal(start.challenge.phase,'captcha');assert.equal(start.challenge.asciiArt,'A B C\nD E F');assert.equal(JSON.stringify(start).includes(accountPassword),false);
    f.advance();const challenge=await f.account.continue({id:start.challenge.id,captchaSolution:'ABCDEF'});assert.equal(challenge.challenge.phase,'2fa');assert.equal(f.calls[1].parameters.captcha_solution,'ABCDEF');
    f.advance();const result=await f.account.continue({id:challenge.challenge.id,code2fa:'123456'});assert.equal(result.loggedIn,true);assert.equal(preflights,2);assert.equal(f.calls.at(-1).parameters.secure_token,'second-security-token');assert.equal(f.account.pending,null);
  }finally{await f.close();}
});
test('wrong 2FA preserves a bounded challenge, expiry clears it, and bad credentials never retry automatically',async()=>{
  const f=await fixture(async r=>r.endpoint==='AuthToken/login'?{token:'secure'}:Promise.reject(new WindscribeError(1341)));try{
    const result=await f.login();assert.equal(result.challenge.phase,'2fa');f.advance(180001);await assert.rejects(f.account.continue({id:result.challenge.id,code2fa:'123456'}),{code:708});assert.equal(f.account.pending,null);
  }finally{await f.close();}
  const bad=await fixture(async r=>r.endpoint==='AuthToken/login'?{token:'secure'}:Promise.reject(new WindscribeError(702)));try{await assert.rejects(bad.login(),{code:702});assert.equal(bad.calls.length,2);assert.equal(bad.account.pending,null);}finally{await bad.close();}
});
test('cancelled in-flight login revokes a late session instead of restoring it',async()=>{
  let release,arrived;const started=new Promise(r=>arrived=r);let revoked=false;
  const f=await fixture(async r=>{if(r.endpoint==='AuthToken/login')return {token:'secure'};if(r.method==='POST'){arrived();return new Promise(r=>release=r);}if(r.method==='DELETE'){revoked=true;return {};}});
  try{const login=f.login();await started;await assert.rejects(f.account.refresh(),/در حال/);f.account.cancel();release({...profile});await assert.rejects(login);assert.equal(revoked,true);assert.equal(f.account.state().loggedIn,false);await assert.rejects(fs.access(f.account.file),{code:'ENOENT'});}finally{await f.close();}
});
test('unavailable secure storage supports memory-only login and never writes plaintext fallback',async()=>{
  const codec={available:()=>false,encrypt(){throw Error('Must not encrypt');}};const f=await fixture(null,{vault:codec});try{
    await assert.rejects(f.login(true),{code:'vault'});assert.equal(f.calls.length,0);f.advance();await f.login(false);assert.equal(f.account.state().loggedIn,true);assert.equal(f.account.state().canRemember,false);await assert.rejects(fs.access(f.account.file),{code:'ENOENT'});
  }finally{await f.close();}
});
test('vault write failure keeps a working memory session and reports it without a password',async()=>{
  const codec={available:()=>true,encrypt(){throw Error(accountPassword);}};const f=await fixture(null,{vault:codec});try{const result=await f.login(true);assert.equal(result.loggedIn,true);assert.equal(result.remembered,false);assert.ok(result.error);assert.equal(result.error.includes(accountPassword),false);}finally{await f.close();}
});
test('invalid restored session clears encrypted receipt and credentials stay main-process only',async()=>{
  const f=await fixture();try{
    await f.login(true);const credentials=await f.account.credentials('wstunnel');assert.equal(credentials.password,connectionPassword);assert.equal(f.calls.at(-1).parameters.type,'openvpn');await f.account.credentials('ikev2');assert.equal(f.calls.at(-1).parameters.type,'ikev2');assert.equal(JSON.stringify(f.account.state()).includes(connectionPassword),false);
    let forgotten=false;const restored=new WindscribeAccount({dataDir:f.dir,vault:f.codec,request:async()=>{throw new WindscribeError(701);},onForget:async()=>{forgotten=true;}});await restored.init();assert.equal(restored.state().loggedIn,false);assert.equal(forgotten,true);await assert.rejects(fs.access(f.account.file),{code:'ENOENT'});restored.shutdown();
  }finally{await f.close();}
});
test('logout attempts remote session deletion and clears local token even when network fails',async()=>{
  const f=await fixture(async r=>{if(r.endpoint==='AuthToken/login')return {token:'secure'};if(r.method==='DELETE')throw Error(accountPassword);return {...profile};});try{
    await f.login(true);const result=await f.account.logout();assert.equal(result.loggedIn,false);assert.equal(result.remoteRevoked,false);assert.equal(f.calls.at(-1).token,token);assert.equal(f.account.token,null);assert.ok(result.error);assert.equal(result.error.includes(accountPassword),false);await assert.rejects(fs.access(f.account.file),{code:'ENOENT'});
  }finally{await f.close();}
});
function transportFixture(reply,status=200){
  let captured;const requestImpl=(url,options,onResponse)=>{const req=new EventEmitter();req.setTimeout=()=>{};req.destroy=()=>req.emit('error',Error(accountPassword));req.end=body=>{captured={url:String(url),options,body};const res=new PassThrough();res.statusCode=status;onResponse(res);setImmediate(()=>res.end(JSON.stringify(reply)));};return req;};
  return {requestImpl,get captured(){return captured;}};
}
test('HTTPS transport puts login secrets in POST body, session token in Bearer header, and rejects redirects',async()=>{
  const t=transportFixture({data:{token:'secure'}});await apiRequest({method:'POST',endpoint:'Session',parameters:{username:'user',password:accountPassword,'2fa_code':''},requestImpl:t.requestImpl});
  assert.equal(t.captured.url,'https://api.windscribe.com/Session');assert.equal(t.captured.options.headers.Authorization,undefined);assert.equal(new URLSearchParams(t.captured.body).get('password'),accountPassword);assert.equal(new URLSearchParams(t.captured.body).has('2fa_code'),false);
  const params=new URLSearchParams(t.captured.body);assert.equal(params.get('client_auth_hash'),crypto.createHash('md5').update('952b4412f002315aa50751032fcaab03'+params.get('time')).digest('hex'));
  const auth=transportFixture({data:profile});await apiRequest({method:'GET',endpoint:'Session',token,requestImpl:auth.requestImpl});assert.equal(auth.captured.url.includes(token),false);assert.equal(auth.captured.options.headers.Authorization,'Bearer '+token);
  const redirect=transportFixture({data:{}},302);await assert.rejects(apiRequest({method:'GET',endpoint:'Session',token,requestImpl:redirect.requestImpl}),{code:'redirect'});
});
test('provider error text is never reflected into a message, and arbitrary API endpoints are refused',async()=>{
  const bad=transportFixture({errorCode:702,errorMessage:accountPassword+' '+token},400);await assert.rejects(apiRequest({method:'POST',endpoint:'Session',parameters:{password:accountPassword},requestImpl:bad.requestImpl}),e=>e.code===702&&!e.message.includes(accountPassword)&&!e.message.includes(token));
  await assert.rejects(apiRequest({method:'POST',endpoint:'https://outside.test',parameters:{password:accountPassword}}),/Invalid/);
});
