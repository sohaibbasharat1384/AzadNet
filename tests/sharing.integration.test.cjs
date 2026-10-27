const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const path=require('node:path');
const http=require('node:http');
const net=require('node:net');
const {once}=require('node:events');
const Service=require('../desktop/lib/service.cjs');
const {sharingInfo}=require('../desktop/lib/sharing.cjs');
const listen=s=>new Promise(r=>s.listen(0,'127.0.0.1',()=>r(s.address().port)));
async function freePort(){const s=net.createServer();const port=await listen(s);await new Promise(r=>s.close(r));return port;}
async function request(host,port,credentials){return await new Promise((resolve,reject)=>{const req=http.get({host,port,path:'http://fixture.sharing.test/check',headers:{Host:'fixture.sharing.test',...(credentials?{'Proxy-Authorization':'Basic '+Buffer.from(credentials).toString('base64')}: {})}},res=>{let body='';res.on('data',d=>body+=d);res.on('end',()=>resolve({code:res.statusCode,body}));});req.setTimeout(4000,()=>req.destroy(new Error('LAN fixture timeout')));req.on('error',reject);});}
async function readN(socket,n){for(;;){const data=socket.read(n);if(data)return data;if(socket.destroyed)throw new Error('SOCKS fixture closed');await once(socket,'readable');}}
test('real core shares HTTP/SOCKS5 with LAN password and closes LAN access when disabled',{skip:process.env.AZADNET_TEST_REAL_CORE!=='1',timeout:30000},async t=>{
  const nic=sharingInfo({mixedPort:1},'disconnected').addresses[0];if(!nic){t.skip('No private IPv4 interface on this test host');return;}
  const root=path.resolve(__dirname,'../.tools/tmp');await fs.mkdir(root,{recursive:true});const dir=await fs.mkdtemp(path.join(root,'lan-integration-'));
  const reply=(req,res)=>{if(req.url.includes('generate_204'))setTimeout(()=>{res.writeHead(204);res.end();},10);else res.end('shared-via-selected-proxy');};
  const origin=http.createServer(reply);
  const originPort=await listen(origin);let forwarded=0;
  const upstream=http.createServer((req,res)=>{forwarded++;reply(req,res);});
  upstream.on('connect',(_req,socket,head)=>{forwarded++;const peer=net.connect(originPort,'127.0.0.1',()=>{socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');if(head.length)peer.write(head);socket.pipe(peer);peer.pipe(socket);});peer.on('error',()=>socket.destroy());socket.on('error',()=>peer.destroy());socket.on('close',()=>peer.destroy());});
  let svc,socks;
  try{
    const upstreamPort=await listen(upstream),mixedPort=await freePort(),controllerPort=await freePort();svc=new Service({dataDir:dir,corePath:path.resolve(__dirname,'../resources/core',process.platform==='win32'?'mihomo.exe':'mihomo'),delayUrl:'http://fixture.sharing.test/generate_204'});await svc.init();
    await svc.saveSettings({mixedPort,controllerPort,routingMode:'global'});
    await svc.importText(`proxies:\n - {name: Sharing fixture, type: http, server: 127.0.0.1, port: ${upstreamPort}}`);
    await svc.start();await svc.updateSharing({allowLan:true,lanUsername:'fixture',lanPassword:'strong-fixture-pass',lanPasswordRequired:true});
    assert.equal((await request(nic.address,mixedPort)).code,407);assert.equal((await request(nic.address,mixedPort,'fixture:wrong')).code,403);
    const result=await request(nic.address,mixedPort,'fixture:strong-fixture-pass');assert.equal(result.code,200);assert.equal(result.body,'shared-via-selected-proxy');assert.ok(forwarded>0);
    socks=net.connect(mixedPort,nic.address);const timer=setTimeout(()=>socks.destroy(new Error('SOCKS timeout')),5000);
    try{await once(socks,'connect');socks.write(Buffer.from([5,1,2]));assert.deepEqual(await readN(socks,2),Buffer.from([5,2]));
      const user=Buffer.from('fixture'),pass=Buffer.from('strong-fixture-pass');socks.write(Buffer.concat([Buffer.from([1,user.length]),user,Buffer.from([pass.length]),pass]));assert.deepEqual(await readN(socks,2),Buffer.from([1,0]));
      const host=Buffer.from('fixture.sharing.test');socks.write(Buffer.concat([Buffer.from([5,1,0,3,host.length]),host,Buffer.from([0,80])]));const reply=await readN(socks,4);assert.equal(reply[1],0);await readN(socks,reply[3]===1?6:18);
    }finally{clearTimeout(timer);socks.destroy();}
    await svc.updateSharing({allowLan:false});await assert.rejects(request(nic.address,mixedPort,'fixture:strong-fixture-pass'));assert.equal((await request('127.0.0.1',mixedPort)).code,200);
  }finally{if(svc)await svc.shutdown();socks?.destroy();await new Promise(r=>upstream.close(r));await new Promise(r=>origin.close(r));await fs.rm(dir,{recursive:true,force:true});}
});
