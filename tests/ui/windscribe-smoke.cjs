// Run with Electron, not node:test. Uses synthetic profiles and never starts a VPN.
'use strict';
const {app,BrowserWindow,ipcMain,safeStorage}=require('electron');
const fs=require('node:fs/promises');
const path=require('node:path');
const assert=require('node:assert/strict');
const Service=require('../../desktop/lib/service.cjs');
const {WindscribeAccount,WindscribeError}=require('../../desktop/lib/windscribe-account.cjs');
const root=path.resolve(__dirname,'../..');
const output=path.join(root,'analysis/windscribe-account-ui');
app.setPath('userData',path.join(root,'.tools/windscribe-ui-user'));
let window,service,account;
const pause=ms=>new Promise(r=>setTimeout(r,ms));
app.whenReady().then(async()=>{
  await fs.mkdir(output,{recursive:true});
  const dir=await fs.mkdtemp(path.join(app.getPath('userData')+'-'));
  try{
    const runtime={async recover(){},async stop(){},async availability(){return {wireguard:true,udp:true,tcp:true,ikev2:true,stealth:true,wstunnel:true};}};
    service=new Service({dataDir:dir,windscribeRuntime:runtime,openvpnIdentitySupported:true,emit:(event,payload)=>window?.webContents.send('azadnet-event',event,payload)});await service.init();
    let clock=10000,preflights=0,logins=0,imageFixture=null;const accountConnections=[];
    account=new WindscribeAccount({dataDir:dir,now:()=>clock,vault:{available:()=>safeStorage.isEncryptionAvailable()&&(process.platform!=='linux'||safeStorage.getSelectedStorageBackend()!=='basic_text'),encrypt:value=>safeStorage.encryptString(value),decrypt:value=>safeStorage.decryptString(value)},emit:info=>window?.webContents.send('azadnet-event','windscribe-account',info),request:async r=>{
      if(r.endpoint==='AuthToken/login'){preflights++;return logins?{token:'fixture-security-token'}:{token:'fixture-security-token',captcha:r.parameters.captcha_type==='ascii'?{ascii_art:('WIDE SYNTHETIC TEXT '.repeat(8)+'\n').repeat(8)}:imageFixture};}
      if(r.endpoint==='ServerCredentials')return {username:Buffer.from('fixture-config-user').toString('base64'),password:Buffer.from('fixture-config-password').toString('base64')};
      if(r.method==='POST'&&++logins===1){assert.equal(r.parameters.captcha_solution,'170');assert.ok(Object.keys(r.parameters).some(key=>key.startsWith('captcha_trail[x]')));throw new WindscribeError(1340);}
      return {session_auth_hash:'fixture-account-session',user_id:'fixture-id',username:'fixture-user',status:1,is_premium:1,traffic_used:1024,traffic_max:-1};
    }});
    const key=Buffer.alloc(32,7).toString('base64');
    const wg=`[Interface]\nPrivateKey=${key}\nAddress=10.1.1.2/32\n[Peer]\nPublicKey=${key}\nAllowedIPs=0.0.0.0/0\nEndpoint=node.example:443\n`;
    const ovpn='client\ndev tun\nproto tcp-client\nremote node.example 443\nauth-user-pass\nverify-x509-name node name\n<ca>\n-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n</ca>\n';
    ipcMain.handle('azadnet',async(_event,action,...args)=>{
      try{
        if(action==='state')return service.getState();
        if(action==='windscribeInfo')return runtime.availability();
        if(action==='windscribeAccount')return account.state();
        if(action==='windscribeLogin'){clock+=2100;return account.begin(args[0]);}
        if(action==='windscribeLoginContinue'){clock+=2100;return account.continue(args[0]);}
        if(action==='windscribeCaptchaRefresh'){clock+=2100;return account.refreshCaptcha(args[0]);}
        if(action==='windscribeLoginCancel')return account.cancel();
        if(action==='windscribeAccountRefresh')return account.refresh();
        if(action==='windscribeLocations')return {loaded:true,updatedAt:Date.now(),ports:{wireguard:[443,80],udp:[443,1194],tcp:[443],ikev2:[500],stealth:[443],wstunnel:[443]},locations:[{id:'10',country:'Fixture Country',countryCode:'NL',city:'Amsterdam',nickname:'Fixture <img src=x onerror=bad()>',available:true,protocols:['wireguard','udp','tcp','ikev2','stealth','wstunnel'],nodeCount:2,load:30},{id:'11',country:'Fixture Country',countryCode:'NL',city:'Locked',nickname:'Pro',available:false,protocols:[],nodeCount:0,premium:true}]};
        if(action==='windscribeConnect'){accountConnections.push(args[0]);return service.getState();}
        if(action==='windscribeLogout')return account.logout();
        if(action==='windscribeIKEAdd'||action==='windscribeImport'){const o={...args[0]};if(o.useAccount&&o.protocol!=='wireguard')Object.assign(o,await account.credentials(o.protocol));return service.importWindscribe(o.protocol==='ikev2'?[]:[{name:o.protocol+'.conf',text:o.protocol==='wireguard'?wg:o.protocol==='udp'?ovpn.replace('tcp-client','udp'):ovpn}],o);}
        if(action==='select')return service.selectServer(args[0]);
        throw Error('Unexpected UI smoke operation: '+action);
      }catch(e){return {__error:e.message};}
    });
    const errors=[];
    window=new BrowserWindow({width:1180,height:900,show:false,webPreferences:{preload:path.join(root,'desktop/preload.cjs'),contextIsolation:true,nodeIntegration:false,sandbox:true,backgroundThrottling:false}});
    window.webContents.on('console-message',e=>{if(e.level==='error')errors.push(e.message);});
    await window.loadFile(path.join(root,'desktop/renderer/index.html'));await pause(250);
    const js=source=>window.webContents.executeJavaScript(source);
    // These are our own simple geometric test images, not a provider challenge.
    imageFixture=await js(`(()=>{const background=document.createElement('canvas');background.width=320;background.height=140;const ctx=background.getContext('2d');ctx.fillStyle='#6e99bb';ctx.fillRect(0,0,320,140);ctx.fillStyle='#1b3145';ctx.fillRect(170,30,40,40);const piece=document.createElement('canvas');piece.width=40;piece.height=40;piece.getContext('2d').fillStyle='#efc26d';piece.getContext('2d').fillRect(0,0,40,40);return {background:background.toDataURL('image/png'),slider:piece.toDataURL('image/png'),top:30};})()`);
    await js(`document.querySelector('[data-page="windscribe"]').click()`);await pause(100);
    assert.equal(await js(`getComputedStyle(document.querySelector('#windscribe-account-cancel')).display`),'none');
    await fs.writeFile(path.join(output,'login.png'),(await window.webContents.capturePage()).toPNG());
    await js(`(()=>{const f=document.querySelector('#windscribe-login-form');f.elements.accountUsername.value='fixture-user';f.elements.accountPassword.value='fixture-account-only-password';f.requestSubmit();})()`);
    for(let i=0;i<50&&account.state().challenge?.phase!=='captcha';i++)await pause(30);await pause(150);
    assert.equal(account.state().challenge.phase,'captcha');assert.equal(await js(`document.querySelector('#windscribe-account-password').value`),'');assert.equal(await js(`document.querySelector('#windscribe-account-captcha').hidden`),false);
    assert.equal(await js(`document.querySelector('#windscribe-captcha-dialog').open`),true);assert.equal(await js(`document.querySelector('#windscribe-captcha-submit').disabled`),true);
    await fs.writeFile(path.join(output,'captcha.png'),(await window.webContents.capturePage()).toPNG());
    window.setSize(900,670);await pause(150);assert.equal(await js(`(()=>{const r=document.querySelector('#windscribe-captcha-dialog').getBoundingClientRect();return r.left>=0&&r.right<=innerWidth&&r.height<=innerHeight;})()`),true);await fs.writeFile(path.join(output,'captcha-compact.png'),(await window.webContents.capturePage()).toPNG());window.setSize(1180,900);await pause(150);
    await js(`document.querySelector('#windscribe-captcha-handle').dispatchEvent(new KeyboardEvent('keydown',{key:'ArrowRight',shiftKey:true,bubbles:true}))`);assert.equal(await js(`document.querySelector('#windscribe-captcha-handle').getAttribute('aria-valuenow')`),'10');
    await js(`document.querySelector('#windscribe-captcha-switch').click()`);for(let i=0;i<50&&account.state().challenge?.captchaType!=='ascii';i++)await pause(30);await pause(100);
    assert.equal(await js(`getComputedStyle(document.querySelector('#windscribe-account-ascii')).whiteSpace`),'pre');assert.equal(await js(`getComputedStyle(document.querySelector('#windscribe-account-ascii')).fontVariantLigatures`),'none');
    await js(`document.querySelector('#windscribe-captcha-larger').click();document.querySelector('#windscribe-captcha-larger').click()`);await pause(80);await fs.writeFile(path.join(output,'captcha-text-zoom.png'),(await window.webContents.capturePage()).toPNG());
    await js(`document.querySelector('#windscribe-captcha-switch').click()`);for(let i=0;i<50&&account.state().challenge?.captchaType!=='image';i++)await pause(30);await pause(150);
    // Emulate pointer events only against the known, synthetic fixture geometry.
    await js(`(()=>{const handle=document.querySelector('#windscribe-captcha-handle'),stage=document.querySelector('#windscribe-captcha-stage'),r=handle.getBoundingClientRect(),scale=stage.getBoundingClientRect().width/320;handle.setPointerCapture=()=>{};const start=r.left+r.width/2,y=r.top+r.height/2;handle.dispatchEvent(new PointerEvent('pointerdown',{pointerId:99,button:0,clientX:start,clientY:y}));for(const offset of [20,80,170])handle.dispatchEvent(new PointerEvent('pointermove',{pointerId:99,clientX:start+offset*scale,clientY:y}));handle.dispatchEvent(new PointerEvent('pointerup',{pointerId:99}));})()`);
    assert.equal(await js(`document.querySelector('#windscribe-captcha-piece').style.left`),'53.125%');assert.equal(await js(`document.querySelector('#windscribe-captcha-submit').disabled`),false);
    await js(`document.querySelector('#windscribe-captcha-form').requestSubmit()`);
    for(let i=0;i<50&&account.state().challenge?.phase!=='2fa';i++)await pause(30);await pause(100);assert.equal(account.state().challenge.phase,'2fa');
    await js(`document.querySelector('#windscribe-account-2fa').value='۱۲۳۴۵۶';document.querySelector('#windscribe-login-form').requestSubmit()`);
    for(let i=0;i<50&&!account.state().loggedIn;i++)await pause(30);await pause(100);assert.equal(account.state().loggedIn,true);assert.equal(await js(`document.querySelector('#windscribe-login-form').hidden`),true);
    assert.equal(await js(`getComputedStyle(document.querySelector('#windscribe-login-form')).display`),'none');
    if(account.remembered){const encrypted=await fs.readFile(account.file);assert.equal(encrypted.includes(Buffer.from('fixture-account-only-password')),false);assert.equal(encrypted.includes(Buffer.from('fixture-account-session')),false);assert.equal(safeStorage.decryptString(encrypted).includes('fixture-account-only-password'),false);}
    for(const protocol of ['wireguard','udp','tcp','ikev2','stealth','wstunnel']){
      const fields=await js(`(()=>{const f=document.querySelector('#windscribe-form');f.elements.protocol.value=${JSON.stringify(protocol)};f.elements.protocol.dispatchEvent(new Event('change'));return {credentials:!document.querySelector('#windscribe-credentials').hidden,ike:!document.querySelector('#windscribe-ike-fields').hidden,outer:!document.querySelector('#windscribe-outer-fields').hidden};})()`);
      assert.equal(fields.credentials,false);assert.equal(fields.ike,protocol==='ikev2');assert.equal(fields.outer,['stealth','wstunnel'].includes(protocol));
      await js(`(()=>{const f=document.querySelector('#windscribe-form');f.elements.username.value='fixture-user';f.elements.password.value='fixture-only-secret';f.elements.name.value='IKE Test';f.elements.server.value='ike.example';f.requestSubmit();})()`);
      for(let n=0;n<50;n++){if(!(await js(`document.querySelector('#windscribe-import').disabled`)))break;await pause(50);}
      assert.equal(await js(`document.querySelector('#windscribe-import-error').textContent`),'');assert.equal(await js(`document.querySelector('#windscribe-form').elements.password.value`),'');
    }
    assert.equal(service.subscriptions.length,6);assert.equal(await js(`document.querySelectorAll('#windscribe-profiles .subscription-item').length`),6);
    for(let i=0;i<50&&!await js(`document.querySelector('#windscribe-locations button')!==null`);i++)await pause(30);
    await js(`document.querySelector('#windscribe-location-card').scrollIntoView()`);await pause(100);
    assert.equal(await js(`document.querySelector('#windscribe-location-card').hidden`),false);assert.equal(await js(`document.querySelectorAll('#windscribe-locations img').length`),0);assert.equal(await js(`document.querySelectorAll('#windscribe-locations button').length`),1);
    assert.equal(await js(`document.querySelector('#windscribe-location-protocol').options.length`),6);
    await js(`document.querySelector('#windscribe-location-available').checked=false;document.querySelector('#windscribe-location-available').dispatchEvent(new Event('input'))`);
    assert.equal(await js(`document.querySelectorAll('#windscribe-locations button').length`),2);assert.equal(await js(`document.querySelector('#windscribe-locations button[data-location-id="11"]').disabled`),true);
    await js(`document.querySelector('#windscribe-location-search').value='no-match';document.querySelector('#windscribe-location-search').dispatchEvent(new Event('input'))`);assert.equal(await js(`document.querySelectorAll('#windscribe-locations button').length`),0);
    await js(`document.querySelector('#windscribe-location-search').value='Amsterdam';document.querySelector('#windscribe-location-search').dispatchEvent(new Event('input'));document.querySelector('#windscribe-location-protocol').value='tcp';document.querySelector('#windscribe-location-protocol').dispatchEvent(new Event('change'))`);
    window.setSize(1181,900);await pause(120);window.setSize(1180,900);await js(`document.querySelector('#windscribe-location-card').scrollIntoView()`);await pause(200);await fs.writeFile(path.join(output,'catalog-wide.png'),(await window.webContents.capturePage()).toPNG());window.setSize(900,670);await pause(150);assert.equal(await js(`document.documentElement.scrollWidth<=window.innerWidth`),true);await fs.writeFile(path.join(output,'catalog-compact.png'),(await window.webContents.capturePage()).toPNG());window.setSize(1180,900);
    await js(`document.querySelector('#windscribe-locations button[data-location-id="10"]').click()`);for(let i=0;i<50&&!accountConnections.length;i++)await pause(30);assert.deepEqual(accountConnections,[{locationId:'10',protocol:'tcp',port:443}]);await pause(100);await js(`document.querySelector('[data-page="windscribe"]').click()`);await pause(100);
    assert.equal(service.proxyList().find(p=>p.type==='ikev2').password,'fixture-config-password');assert.equal(JSON.stringify(service.getState()).includes('fixture-config-password'),false);
    await pause(300);
    await fs.writeFile(path.join(output,'wide.png'),(await window.webContents.capturePage()).toPNG());
    window.setSize(900,670);await pause(150);assert.equal(await js('document.documentElement.scrollWidth<=window.innerWidth'),true);await fs.writeFile(path.join(output,'compact.png'),(await window.webContents.capturePage()).toPNG());
    await js(`document.querySelector('#windscribe-form').elements.protocol.value='ikev2';document.querySelector('#windscribe-protocol').dispatchEvent(new Event('change'));document.querySelector('#windscribe-profiles').scrollIntoView()`);await pause(100);await fs.writeFile(path.join(output,'profiles.png'),(await window.webContents.capturePage()).toPNG());
    const native=service.proxyList().find(p=>p.type==='ikev2');await service.selectServer(native.name);await js(`document.querySelector('[data-page="home"]').click()`);await pause(100);assert.equal(await js(`document.querySelector('#tun-mode').disabled`),true);
    await js(`document.querySelector('[data-page="windscribe"]').click()`);await pause(100);await js(`document.querySelector('#windscribe-account-logout').click()`);for(let i=0;i<50&&account.state().loggedIn;i++)await pause(30);await pause(100);assert.equal(account.state().loggedIn,false);assert.equal(service.subscriptions.length,6);await assert.rejects(fs.access(account.file),{code:'ENOENT'});
    assert.equal(await js(`document.querySelector('#windscribe-login-form').hidden`),false);assert.equal(await js(`document.querySelector('#windscribe-location-card').hidden`),true);assert.deepEqual(errors,[]);await fs.writeFile(path.join(output,'result.json'),JSON.stringify({passed:true,profiles:6,imageCaptcha:true,asciiZoom:true,twoFactor:true,accountCatalog:true,catalogFiltering:true,protocolSelection:true,accountConnect:true,logout:true,consoleErrors:errors},null,2));
    console.log('Windscribe UI smoke passed: synthetic CAPTCHA/2FA, account catalog/filtering, six protocols, one-click connection, OS vault, imports and logout.');
  }finally{account?.shutdown();await service?.shutdown();window?.destroy();if(!dir.startsWith(path.join(root,'.tools')+path.sep))throw Error('Unsafe fixture cleanup');await fs.rm(dir,{recursive:true,force:true});}
}).then(()=>app.exit(0)).catch(e=>{console.error(e);app.exit(1);});
