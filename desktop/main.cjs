const { app, BrowserWindow, ipcMain, dialog, Menu, Tray, nativeImage } = require('electron');
const path = require('node:path');
const fs = require('node:fs/promises');
const crypto = require('node:crypto');
const { Service } = require('./lib/service.cjs');
let window, service, quitting = false;
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
  let fragmentsSupported=false;
  try {
    const identity=JSON.parse(await fs.readFile(path.join(path.dirname(corePath),'build.json'),'utf8'));
    const digest=crypto.createHash('sha256').update(await fs.readFile(corePath)).digest('hex');
    fragmentsSupported=identity.supportsFragments===true && identity.sha256===digest;
  } catch {}
  service = new Service({ dataDir:path.join(app.getPath('userData'),'profiles'),corePath,fragmentsSupported,emit:(event,payload) => {
    if (window && !window.isDestroyed()) window.webContents.send('azadnet-event',event,payload);
  }});
  await service.init();
  ipcMain.handle('azadnet', async (e,action,...args) => {
    if(e.sender !== window.webContents) throw new Error('Untrusted sender');
    try {
      switch(action) {
        case 'state': return await service.getState();
        case 'settings': return await service.saveSettings(args[0]);
        case 'importText': return await service.importText(...args);
        case 'importUrl': return await service.importUrl(...args);
        case 'refresh': return await service.refreshSubscription(args[0]);
        case 'remove': return await service.removeSubscription(args[0]);
        case 'select': return await service.selectServer(args[0]);
        case 'start': return await service.start();
        case 'stop': return await service.stop();
        case 'test': return await service.testServers();
        case 'speed': return await service.speedTest();
        case 'logs': return service.getLogs();
        case 'traffic': return await service.traffic();
        case 'openFile': {
          const result = await dialog.showOpenDialog(window,{properties:['openFile'],filters:[{name:'Profiles',extensions:['yaml','yml','json','txt','conf']}]});
          if(result.canceled) return null;
          const stat = await fs.stat(result.filePaths[0]);
          if(stat.size>5*1024*1024) throw new Error('حداکثر اندازهٔ فایل ۵ مگابایت است.');
          return await service.importText(await fs.readFile(result.filePaths[0],'utf8'),path.basename(result.filePaths[0]));
        }
        case 'saveLogs': {
          const result = await dialog.showSaveDialog(window,{defaultPath:'azadnet-diagnostics.txt'});
          if(!result.canceled) await fs.writeFile(result.filePath,JSON.stringify(service.getLogs(),null,2));
          return !result.canceled;
        }
        default: throw new Error('Unknown action');
      }
    } catch(error) { return {__error:error.message}; }
  });
  createWindow();
});
app.on('window-all-closed', () => app.quit());
app.on('before-quit', e => {
  if(quitting || !service) return;
  e.preventDefault(); quitting=true;
  Promise.resolve(service.shutdown()).finally(() => app.quit());
});
process.on('uncaughtException', error => { console.error(error); if(service) Promise.resolve(service.shutdown()).finally(()=>app.exit(1)); else app.exit(1); });
