const { app, BrowserWindow, ipcMain, dialog, clipboard, shell, safeStorage, Menu, Tray, nativeImage } = require('electron');
const path = require('node:path');
const fs = require('node:fs/promises');
const crypto = require('node:crypto');
const { Service } = require('./lib/service.cjs');
const {PROTOCOLS}=require('./lib/windscribe-import.cjs');
const {WindscribeAccount}=require('./lib/windscribe-account.cjs');
let window, service, windscribeAccount, quitting = false;
if(process.env.AZADNET_DATA_DIR) app.setPath('userData',path.resolve(process.env.AZADNET_DATA_DIR));
const hasLock=app.requestSingleInstanceLock();
if(!hasLock) app.quit();
app.on('second-instance',()=>{if(window){if(window.isMinimized())window.restore();window.show();window.focus();}});
const corePath = process.env.AZADNET_CORE_PATH || path.join(app.isPackaged ? process.resourcesPath : path.join(__dirname,'..','resources'), 'core', process.platform === 'win32' ? 'mihomo.exe' : 'mihomo');
function createWindow() {
  window = new BrowserWindow({ width:1180,height:900,minWidth:900,minHeight:670, backgroundColor:'#050e09',title:'آزادنت · اینترنت آزاد',autoHideMenuBar:true,
    webPreferences:{preload:path.join(__dirname,'preload.cjs'),contextIsolation:true,nodeIntegration:false,sandbox:true} });
  window.loadFile(path.join(__dirname,'renderer','index.html'));
  window.webContents.on('console-message', event => { if(event.level==='error') console.error(event.message); });
  if(!app.isPackaged && process.env.AZADNET_SCREENSHOT) window.webContents.once('did-finish-load',async()=>{
    await new Promise(resolve=>setTimeout(resolve,1200));
    try{await fs.writeFile(process.env.AZADNET_SCREENSHOT,(await window.webContents.capturePage()).toPNG());}catch(error){console.error(error.message);}
  });
  window.webContents.setWindowOpenHandler(() => ({action:'deny'}));
  window.webContents.on('will-navigate', e => e.preventDefault());
}
if(hasLock) app.whenReady().then(async () => {
  let fragmentsSupported=false,openvpnIdentitySupported=false;
  try {
    const identity=JSON.parse(await fs.readFile(path.join(path.dirname(corePath),'build.json'),'utf8'));
    const digest=crypto.createHash('sha256').update(await fs.readFile(corePath)).digest('hex');
    fragmentsSupported=identity.supportsFragments===true && identity.sha256===digest;
    openvpnIdentitySupported=identity.supportsOpenVPNIdentity===true && identity.sha256===digest;
  } catch {}
  service = new Service({ dataDir:path.join(app.getPath('userData'),'profiles'),corePath,fragmentsSupported,openvpnIdentitySupported,emit:(event,payload) => {
    if (window && !window.isDestroyed()) window.webContents.send('azadnet-event',event,payload);
  }});
  await service.init();
  windscribeAccount=new WindscribeAccount({dataDir:path.join(app.getPath('userData'),'profiles'),vault:{
    available:()=>safeStorage.isEncryptionAvailable()&&(process.platform!=='linux'||safeStorage.getSelectedStorageBackend()!=='basic_text'),
    encrypt:value=>safeStorage.encryptString(value),decrypt:bytes=>safeStorage.decryptString(bytes)
  },emit:payload=>{if(window&&!window.isDestroyed())window.webContents.send('azadnet-event','windscribe-account',payload);}});
  async function windscribeOptions(input,protocol=input?.protocol){
    service.requireIdle();const options={...input,protocol};delete options.accountId;
    if(input?.useAccount===true&&protocol!=='wireguard')Object.assign(options,await windscribeAccount.credentials(protocol));
    return options;
  }
  ipcMain.handle('azadnet', async (e,action,...args) => {
    if(e.sender !== window.webContents) throw new Error('Untrusted sender');
    try {
      if(service.sharingUpdating&&!['state','sharing','logs','traffic'].includes(action))throw new Error('در حال اعمال تنظیمات اشتراک‌گذاری؛ کمی صبر کنید.');
      switch(action) {
        case 'state': return await service.getState();
        case 'windscribeInfo': return await service.windscribeAvailability();
        case 'windscribeAccount': return windscribeAccount.state();
        case 'windscribeLogin': return await windscribeAccount.begin(args[0]);
        case 'windscribeLoginContinue': return await windscribeAccount.continue(args[0]);
        case 'windscribeCaptchaRefresh': return await windscribeAccount.refreshCaptcha(args[0]);
        case 'windscribeLoginCancel': return windscribeAccount.cancel();
        case 'windscribeAccountRefresh': return await windscribeAccount.refresh();
        case 'windscribeLogout': return await windscribeAccount.logout();
        case 'windscribeTest': return await service.testServers({source:'windscribe'});
        case 'windscribeIKEAdd': return await service.importWindscribe([],await windscribeOptions(args[0],'ikev2'));
        case 'windscribeGenerator': {
          const protocol=args[0]==='ikev2'?'ikev2':args[0]==='wireguard'?'wireguard':'openvpn';
          await shell.openExternal(`https://windscribe.com/myaccount/config-generator#${protocol}`);return true;
        }
        case 'windscribeImport': {
          const options=args[0];if(!options||!PROTOCOLS.includes(options.protocol)||options.protocol==='ikev2')throw new Error('پروتکل فایل Windscribe را انتخاب کنید.');
          const result=await dialog.showOpenDialog(window,{properties:['openFile','multiSelections'],filters:[{name:options.protocol==='wireguard'?'WireGuard':'OpenVPN',extensions:[options.protocol==='wireguard'?'conf':'ovpn']}]});
          if(result.canceled)return null;if(result.filePaths.length>32)throw new Error('هر بار حداکثر ۳۲ فایل انتخاب کنید.');
          const files=[];for(const file of result.filePaths){const stat=await fs.stat(file);if(!stat.isFile()||stat.size>256*1024)throw new Error('فایل کانفیگ باید حداکثر ۲۵۶ کیلوبایت باشد.');files.push({name:path.basename(file),text:await fs.readFile(file,'utf8')});}
          return await service.importWindscribe(files,await windscribeOptions(options));
        }
        case 'officialStatus': return await service.checkOfficialLicense();
        case 'officialImport': return await service.importOfficialServers();
        case 'offlineStatus': return await service.checkOfflineLicense();
        case 'offlineRequest': {
          const result=await dialog.showSaveDialog(window,{defaultPath:'azadnet-ubuntu-request.json',filters:[{name:'AzadNet request',extensions:['json']}]});if(result.canceled)return null;
          await fs.writeFile(result.filePath,await service.createOfflineRequest(),{mode:0o600});return true;
        }
        case 'offlineExport': {
          const request=await dialog.showOpenDialog(window,{properties:['openFile'],filters:[{name:'Ubuntu request',extensions:['json']}]});if(request.canceled)return null;
          if((await fs.stat(request.filePaths[0])).size>16384)throw new Error('فایل درخواست بیش از حد بزرگ است.');
          const exported=await service.exportOffline(await fs.readFile(request.filePaths[0],'utf8'));
          const result=await dialog.showSaveDialog(window,{defaultPath:'azadnet-ubuntu.azadnet',filters:[{name:'Encrypted AzadNet transfer',extensions:['azadnet']}]});if(result.canceled)return null;
          await fs.writeFile(result.filePath,exported.text,{mode:0o600});return exported.summary;
        }
        case 'offlineImport': {
          const result=await dialog.showOpenDialog(window,{properties:['openFile'],filters:[{name:'Encrypted AzadNet transfer',extensions:['azadnet']}]});if(result.canceled)return null;
          if((await fs.stat(result.filePaths[0])).size>12*1024*1024)throw new Error('فایل انتقال بیش از حد بزرگ است.');
          const text=await fs.readFile(result.filePaths[0],'utf8'),preview=await service.offlineTransfer.preview(text);
          const approval=await dialog.showMessageBox(window,{type:'question',title:'تأیید صادرکنندهٔ بسته',message:'اثر انگشت را با مقداری که نسخهٔ ویندوز نمایش داده مقایسه کنید.',detail:`${preview.issuerFingerprint}\n\nتعداد سرور: ${preview.count}\nپایان اعتبار: ${new Date(preview.expiresAt*1000).toLocaleString('fa-IR')}\n\nاین بسته رسید محلی کلاینت مستقل است و لایسنس رسمی اوبونتوی ارائه‌دهنده نیست.`,buttons:['مطابقت دارد؛ وارد شود','لغو'],defaultId:1,cancelId:1});
          if(approval.response!==0)return null;return await service.importOffline(text,preview.issuerFingerprint);
        }
        case 'settings': return await service.saveSettings(args[0]);
        case 'sharing': return service.getSharing();
        case 'setSharing': return await service.updateSharing(args[0]);
        case 'regenerateSharing': return await service.updateSharing({}, {regeneratePassword:true});
        case 'copySharing': clipboard.writeText(service.getSharingText());return true;
        case 'importText': return await service.importText(...args);
        case 'importUrl': return await service.importUrl(...args);
        case 'refresh': return await service.refreshSubscription(args[0]);
        case 'remove': return await service.removeSubscription(args[0]);
        case 'select': return await service.selectServer(args[0]);
        case 'start': return await service.start();
        case 'stop': return await service.stop();
        case 'test': return await service.testServers();
        case 'speed': return await service.speedTest();
        case 'logs': return [...service.getLogs(),...windscribeAccount.getDiagnostics()].sort((a,b)=>a.time.localeCompare(b.time));
        case 'traffic': return await service.traffic();
        case 'openFile': {
          const result = await dialog.showOpenDialog(window,{properties:['openFile'],filters:[{name:'Profiles',extensions:['yaml','yml','json','txt','conf','ovpn']}]});
          if(result.canceled) return null;
          const stat = await fs.stat(result.filePaths[0]);
          if(stat.size>5*1024*1024) throw new Error('حداکثر اندازهٔ فایل ۵ مگابایت است.');
          return await service.importText(await fs.readFile(result.filePaths[0],'utf8'),path.basename(result.filePaths[0]));
        }
        case 'saveLogs': {
          const result = await dialog.showSaveDialog(window,{defaultPath:'azadnet-diagnostics.txt'});
          if(!result.canceled) await fs.writeFile(result.filePath,JSON.stringify([...service.getLogs(),...windscribeAccount.getDiagnostics()].sort((a,b)=>a.time.localeCompare(b.time)),null,2));
          return !result.canceled;
        }
        default: throw new Error('Unknown action');
      }
    } catch(error) { return {__error:error.message}; }
  });
  createWindow();
  void windscribeAccount.init();
});
app.on('window-all-closed', () => app.quit());
app.on('before-quit', e => {
  if(quitting || !service) return;
  e.preventDefault(); quitting=true;
  windscribeAccount?.shutdown();
  Promise.resolve(service.shutdown()).finally(() => app.quit());
});
process.on('uncaughtException', error => { console.error(error); if(service) Promise.resolve(service.shutdown()).finally(()=>app.exit(1)); else app.exit(1); });
