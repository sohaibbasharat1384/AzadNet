'use strict';
const crypto=require('node:crypto');
const fs=require('node:fs/promises');
const path=require('node:path');
const {parseSubscription}=require('./subscriptions.cjs');
const MAX_FILE=12*1024*1024;
const hash=value=>crypto.createHash('sha256').update(value).digest('hex');
const der=key=>crypto.createPublicKey(key).export({type:'spki',format:'der'});
const publicKey=(text,type)=>{const key=crypto.createPublicKey({key:Buffer.from(text,'base64'),format:'der',type:'spki'});if(key.asymmetricKeyType!==type)throw new Error('نوع کلید بسته نامعتبر است.');return key;};
function parse(text){if(typeof text!=='string'||Buffer.byteLength(text)>MAX_FILE)throw new Error('اندازهٔ فایل انتقال نامعتبر است.');try{return JSON.parse(text.replace(/^\uFEFF/,''));}catch{throw new Error('فایل انتقال معتبر نیست.');}}
function bytes(text,size){if(typeof text!=='string'||!/^[A-Za-z0-9+/]+={0,2}$/.test(text))throw new Error('دادهٔ رمزگذاری‌شده نامعتبر است.');const b=Buffer.from(text,'base64');if(size&&b.length!==size)throw new Error('اندازهٔ دادهٔ رمزگذاری‌شده نامعتبر است.');return b;}
async function writePrivate(file,value){const temp=file+'.'+crypto.randomBytes(6).toString('hex')+'.tmp';await fs.writeFile(temp,value,{mode:0o600});try{await fs.rename(temp,file);}catch(e){await fs.rm(temp,{force:true});throw e;}}
class OfflineTransfer{
  constructor({dataDir,now=()=>Date.now()}={}){this.dir=path.join(dataDir,'offline-transfer');this.now=now;}
  async key(name,type,create=true){
    await fs.mkdir(this.dir,{recursive:true,mode:0o700});const file=path.join(this.dir,name+'.pem');
    try{const key=crypto.createPrivateKey(await fs.readFile(file));if(key.asymmetricKeyType!==type)throw new Error('کلید نصب آسیب دیده است.');return key;}
    catch(e){if(e.code!=='ENOENT'||!create)throw e;const pair=crypto.generateKeyPairSync(type);await fs.writeFile(file,pair.privateKey.export({type:'pkcs8',format:'pem'}),{mode:0o600,flag:'wx'});return pair.privateKey;}
  }
  async request(){const key=await this.key('recipient','x25519');const pub=der(key);return JSON.stringify({format:'AzadNetTransferRequest',version:1,recipientId:hash(pub),publicKey:pub.toString('base64')},null,2);}
  validateLicense(license){
    const time=this.now(),expiresAt=Number(license?.expiresAt),createdAt=Number(license?.createdAt);
    if(!Number.isSafeInteger(expiresAt)||!Number.isSafeInteger(createdAt)||createdAt>time+300000||expiresAt*1000<=time||expiresAt*1000<=createdAt||expiresAt*1000-createdAt>366*86400000)throw new Error('اعتبار بسته پایان یافته یا تاریخ آن نامعتبر است.');
    return {available:true,active:true,mode:'offline-transfer',verification:'local-windows-snapshot',planName:String(license.planName||'اشتراک منتقل‌شده').slice(0,120),expiresAt,createdAt,daysLeft:Math.ceil((expiresAt*1000-time)/86400000)};
  }
  async export(requestText,{license,proxies}){
    if(!license?.active)throw new Error('برای انتقال، لایسنس نسخهٔ رسمی باید فعال باشد.');
    const validity=this.validateLicense({planName:license.planName,expiresAt:license.expiresAt,createdAt:this.now()});
    const request=parse(requestText);if(request.format!=='AzadNetTransferRequest'||request.version!==1)throw new Error('فایل درخواست اوبونتو معتبر نیست.');
    const recipient=publicKey(request.publicKey,'x25519');if(request.recipientId!==hash(recipient.export({type:'spki',format:'der'})))throw new Error('شناسهٔ درخواست مطابقت ندارد.');
    const checked=parseSubscription(JSON.stringify({proxies})).proxies;
    const signer=await this.key('issuer','ed25519'),ephemeral=crypto.generateKeyPairSync('x25519');
    const header={format:'AzadNetOfflineTransfer',version:1,recipientId:request.recipientId,ephemeralKey:der(ephemeral.privateKey).toString('base64'),salt:crypto.randomBytes(32).toString('base64'),iv:crypto.randomBytes(12).toString('base64'),issuerKey:der(signer).toString('base64')};
    const aad=Buffer.from(JSON.stringify(header));const secret=crypto.diffieHellman({privateKey:ephemeral.privateKey,publicKey:recipient});
    const key=Buffer.from(crypto.hkdfSync('sha256',secret,bytes(header.salt,32),Buffer.from('azadnet-offline-transfer-v1'),32));
    const cipher=crypto.createCipheriv('aes-256-gcm',key,bytes(header.iv,12));cipher.setAAD(aad);
    const ciphertext=Buffer.concat([cipher.update(JSON.stringify({license:validity,proxies:checked}),'utf8'),cipher.final()]).toString('base64'),tag=cipher.getAuthTag().toString('base64');
    const signature=crypto.sign(null,Buffer.from(JSON.stringify([header,ciphertext,tag])),signer).toString('base64');
    return {text:JSON.stringify({header,ciphertext,tag,signature}),summary:{...validity,count:checked.length,issuerFingerprint:hash(der(signer)),recipientId:request.recipientId}};
  }
  async open(text){
    const envelope=parse(text),h=envelope?.header;
    if(!h||h.format!=='AzadNetOfflineTransfer'||h.version!==1)throw new Error('این فایل، بستهٔ انتقال آزادنت نیست.');
    const recipient=await this.key('recipient','x25519',false);
    if(h.recipientId!==hash(der(recipient)))throw new Error('بسته برای نصب دیگری ساخته شده است؛ درخواست همین نصب اوبونتو را صادر کنید.');
    const issuer=publicKey(h.issuerKey,'ed25519');
    if(!crypto.verify(null,Buffer.from(JSON.stringify([h,envelope.ciphertext,envelope.tag])),issuer,bytes(envelope.signature,64)))throw new Error('امضای بسته معتبر نیست یا فایل تغییر کرده است.');
    const secret=crypto.diffieHellman({privateKey:recipient,publicKey:publicKey(h.ephemeralKey,'x25519')});
    const key=Buffer.from(crypto.hkdfSync('sha256',secret,bytes(h.salt,32),Buffer.from('azadnet-offline-transfer-v1'),32));
    const decipher=crypto.createDecipheriv('aes-256-gcm',key,bytes(h.iv,12));decipher.setAAD(Buffer.from(JSON.stringify(h)));decipher.setAuthTag(bytes(envelope.tag,16));
    let payload;try{const plaintext=Buffer.concat([decipher.update(bytes(envelope.ciphertext)),decipher.final()]);if(plaintext.length>8*1024*1024)throw new Error();payload=JSON.parse(plaintext.toString('utf8'));}catch{throw new Error('بازکردن بستهٔ رمزگذاری‌شده ممکن نیست.');}
    const license=this.validateLicense(payload.license),proxies=parseSubscription(JSON.stringify({proxies:payload.proxies})).proxies;
    return {license,proxies,issuerFingerprint:hash(issuer.export({type:'spki',format:'der'})),recipientId:h.recipientId};
  }
  async preview(text){const opened=await this.open(text);return {...opened.license,count:opened.proxies.length,issuerFingerprint:opened.issuerFingerprint,recipientId:opened.recipientId};}
  async mac(text){const key=await this.key('recipient','x25519',false);return crypto.createHmac('sha256',key.export({type:'pkcs8',format:'der'})).update(text).digest('hex');}
  async accept(text,trustedFingerprint){
    const opened=await this.open(text);
    if(trustedFingerprint!==opened.issuerFingerprint)throw new Error('اثر انگشت صادرکننده تأیید نشده است.');
    const at=this.now(),clock={at,mac:await this.mac('clock:'+at)};
    const record={bundle:text,trustedFingerprint,mac:await this.mac(hash(text)+':'+trustedFingerprint)};
    await writePrivate(path.join(this.dir,'clock.json'),JSON.stringify(clock));await writePrivate(path.join(this.dir,'accepted.json'),JSON.stringify(record));
    return opened;
  }
  async status(){
    try{
      const file=path.join(this.dir,'accepted.json');if((await fs.stat(file)).size>MAX_FILE+1024)throw new Error('بسته بیش از حد بزرگ است.');
      const record=JSON.parse(await fs.readFile(file,'utf8'));
      if(record.mac!==await this.mac(hash(record.bundle)+':'+record.trustedFingerprint))throw new Error('اطلاعات فعال‌سازی محلی تغییر کرده است.');
      const opened=await this.open(record.bundle);if(opened.issuerFingerprint!==record.trustedFingerprint)throw new Error('صادرکنندهٔ بسته تغییر کرده است.');
      const clock=JSON.parse(await fs.readFile(path.join(this.dir,'clock.json'),'utf8'));
      if(!Number.isSafeInteger(clock.at)||clock.mac!==await this.mac('clock:'+clock.at)||this.now()<clock.at-3600000)throw new Error('زمان سیستم یا سابقهٔ اعتبار تغییر کرده است.');
      const at=this.now();if(at>clock.at)await writePrivate(path.join(this.dir,'clock.json'),JSON.stringify({at,mac:await this.mac('clock:'+at)}));
      return {...opened.license,issuerFingerprint:opened.issuerFingerprint};
    }catch(e){return {available:true,active:false,mode:'offline-transfer',reason:e.code==='ENOENT'?'no_offline_transfer':e.message};}
  }
}
module.exports={OfflineTransfer,MAX_FILE};
