// Run with Electron, not node:test. Uses synthetic profiles and never starts a VPN.
'use strict';
const {app,BrowserWindow,ipcMain}=require('electron');
const fs=require('node:fs/promises');
const path=require('node:path');
const assert=require('node:assert/strict');
const Service=require('../../desktop/lib/service.cjs');
const root=path.resolve(__dirname,'../..');
const output=path.join(root,'analysis/windscribe-ui');
app.setPath('userData',path.join(root,'.tools/windscribe-ui-user'));
let window,service;
const pause=ms=>new Promise(r=>setTimeout(r,ms));
app.whenReady().then(async()=>{
  await fs.mkdir(output,{recursive:true});
  const dir=await fs.mkdtemp(path.join(app.getPath('userData')+'-'));
  try{
    const runtime={async recover(){},async stop(){},async availability(){return {wireguard:true,udp:true,tcp:true,ikev2:true,stealth:true,wstunnel:true};}};
    service=new Service({dataDir:dir,windscribeRuntime:runtime,openvpnIdentitySupported:true,emit:(event,payload)=>window?.webContents.send('azadnet-event',event,payload)});await service.init();
    const key=Buffer.alloc(32,7).toString('base64');
    const wg=`[Interface]\nPrivateKey=${key}\nAddress=10.1.1.2/32\n[Peer]\nPublicKey=${key}\nAllowedIPs=0.0.0.0/0\nEndpoint=node.example:443\n`;
    const ovpn='client\ndev tun\nproto tcp-client\nremote node.example 443\nauth-user-pass\nverify-x509-name node name\n<ca>\n-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n</ca>\n';
    ipcMain.handle('azadnet',async(_event,action,...args)=>{
      try{
        if(action==='state')return service.getState();
        if(action==='windscribeInfo')return runtime.availability();
        if(action==='windscribeIKEAdd')return service.importWindscribe([],args[0]);
        if(action==='windscribeImport'){const o=args[0];return service.importWindscribe([{name:o.protocol+'.conf',text:o.protocol==='wireguard'?wg:o.protocol==='udp'?ovpn.replace('tcp-client','udp'):ovpn}],o);}
        if(action==='select')return service.selectServer(args[0]);
        throw Error('Unexpected UI smoke operation: '+action);
      }catch(e){return {__error:e.message};}
    });
    const errors=[];
    window=new BrowserWindow({width:1180,height:900,show:false,webPreferences:{preload:path.join(root,'desktop/preload.cjs'),contextIsolation:true,nodeIntegration:false,sandbox:true}});
    window.webContents.on('console-message',e=>{if(e.level==='error')errors.push(e.message);});
    await window.loadFile(path.join(root,'desktop/renderer/index.html'));await pause(250);
    const js=source=>window.webContents.executeJavaScript(source);
    await js(`document.querySelector('[data-page="windscribe"]').click()`);await pause(100);
    for(const protocol of ['wireguard','udp','tcp','ikev2','stealth','wstunnel']){
      const fields=await js(`(()=>{const f=document.querySelector('#windscribe-form');f.elements.protocol.value=${JSON.stringify(protocol)};f.elements.protocol.dispatchEvent(new Event('change'));return {credentials:!document.querySelector('#windscribe-credentials').hidden,ike:!document.querySelector('#windscribe-ike-fields').hidden,outer:!document.querySelector('#windscribe-outer-fields').hidden};})()`);
      assert.equal(fields.credentials,protocol!=='wireguard');assert.equal(fields.ike,protocol==='ikev2');assert.equal(fields.outer,['stealth','wstunnel'].includes(protocol));
      await js(`(()=>{const f=document.querySelector('#windscribe-form');f.elements.username.value='fixture-user';f.elements.password.value='fixture-only-secret';f.elements.name.value='IKE Test';f.elements.server.value='ike.example';f.requestSubmit();})()`);
      for(let n=0;n<50;n++){if(!(await js(`document.querySelector('#windscribe-import').disabled`)))break;await pause(50);}
      assert.equal(await js(`document.querySelector('#windscribe-import-error').textContent`),'');assert.equal(await js(`document.querySelector('#windscribe-form').elements.password.value`),'');
    }
    assert.equal(service.subscriptions.length,6);assert.equal(await js(`document.querySelectorAll('#windscribe-profiles .subscription-item').length`),6);
    await pause(300);
    await fs.writeFile(path.join(output,'wide.png'),(await window.webContents.capturePage()).toPNG());
    window.setSize(900,670);await pause(150);assert.equal(await js('document.documentElement.scrollWidth<=window.innerWidth'),true);await fs.writeFile(path.join(output,'compact.png'),(await window.webContents.capturePage()).toPNG());
    await js(`document.querySelector('#windscribe-form').elements.protocol.value='ikev2';document.querySelector('#windscribe-protocol').dispatchEvent(new Event('change'));document.querySelector('#windscribe-profiles').scrollIntoView()`);await pause(100);await fs.writeFile(path.join(output,'profiles.png'),(await window.webContents.capturePage()).toPNG());
    const native=service.proxyList().find(p=>p.type==='ikev2');await service.selectServer(native.name);await js(`document.querySelector('[data-page="home"]').click()`);await pause(100);assert.equal(await js(`document.querySelector('#tun-mode').disabled`),true);
    assert.deepEqual(errors,[]);await fs.writeFile(path.join(output,'result.json'),JSON.stringify({passed:true,profiles:6,consoleErrors:errors},null,2));
    console.log('Windscribe UI smoke passed: six modes, real service imports, cleared credentials, compact layout, native mode.');
  }finally{await service?.shutdown();window?.destroy();if(!dir.startsWith(path.join(root,'.tools')+path.sep))throw Error('Unsafe fixture cleanup');await fs.rm(dir,{recursive:true,force:true});}
}).then(()=>app.exit(0)).catch(e=>{console.error(e);app.exit(1);});
