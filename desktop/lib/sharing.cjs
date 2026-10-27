'use strict';
const os=require('node:os');
const net=require('node:net');
function privateIPv4(address){
  if(net.isIP(address)!==4)return false;
  const [a,b]=address.split('.').map(Number);
  return a===10 || a===172&&b>=16&&b<=31 || a===192&&b===168 || a===100&&b>=64&&b<=127;
}
function sharingInfo(settings,status,interfaces=os.networkInterfaces()){
  const addresses=[],seen=new Set();
  for(const [interfaceName,entries] of Object.entries(interfaces||{}))for(const entry of entries||[]){
    if(entry.internal||!privateIPv4(entry.address)||seen.has(entry.address))continue;
    seen.add(entry.address);const endpoint=`${entry.address}:${settings.mixedPort}`;
    addresses.push({interfaceName,address:entry.address,port:settings.mixedPort,endpoint});
  }
  addresses.sort((a,b)=>a.interfaceName.localeCompare(b.interfaceName)||a.address.localeCompare(b.address));
  return {enabled:settings.allowLan,active:settings.allowLan&&status==='connected',requiresPassword:settings.lanPasswordRequired,username:settings.lanUsername,password:settings.lanPassword,localEndpoint:`127.0.0.1:${settings.mixedPort}`,addresses};
}
function sharingText(info){
  if(!info.enabled)throw new Error('ابتدا اشتراک‌گذاری وی‌پی‌ان را روشن کنید.');
  if(!info.addresses.length)throw new Error('آدرس خصوصی شبکه پیدا نشد؛ به وای‌فای یا شبکهٔ محلی وصل شوید.');
  return ['اشتراک‌گذاری وی‌پی‌ان · آزادنت',`وضعیت: ${info.active?'فعال':'پس از اتصال VPN فعال می‌شود'}`,'پروتکل: HTTP / SOCKS5',...info.addresses.map(x=>`${x.interfaceName}: ${x.endpoint}`),...(info.requiresPassword?[`نام کاربری: ${info.username}`,`رمز عبور: ${info.password}`]:['رمز عبور: لازم نیست']),'روی دستگاه دیگر، پروکسی را در تنظیمات Wi-Fi یا برنامه به‌صورت دستی تنظیم کنید.'].join('\n');
}
module.exports={privateIPv4,sharingInfo,sharingText};
