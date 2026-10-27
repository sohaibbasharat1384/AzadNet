const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const path=require('node:path');
const http=require('node:http');
const net=require('node:net');
const Service=require('../desktop/lib/service.cjs');
const listen=server=>new Promise(resolve=>server.listen(0,'127.0.0.1',()=>resolve(server.address().port)));
async function freePort(){const server=net.createServer();const port=await listen(server);await new Promise(r=>server.close(r));return port;}
test('real packaged core routes an HTTP request through imported proxy and stops its listeners',{skip:process.env.AZADNET_TEST_REAL_CORE!=='1',timeout:30000},async()=>{
  const root=path.resolve(__dirname,'../.tools/tmp');await fs.mkdir(root,{recursive:true});const dir=await fs.mkdtemp(path.join(root,'core-integration-'));
  const seen=[];const origin=http.createServer((req,res)=>{if(req.url.includes('generate_204')){setTimeout(()=>{res.writeHead(204);res.end();},10);}else{res.writeHead(200,{'content-type':'text/plain'});res.end('azadnet-fixture');}});
  const originPort=await listen(origin);
  const upstream=http.createServer((req,res)=>{seen.push(req.url);if(req.url.includes('generate_204')){setTimeout(()=>{res.writeHead(204);res.end();},10);}else res.end('azadnet-fixture');});
  upstream.on('connect',(req,socket,head)=>{seen.push(req.url);const target=net.connect(originPort,'127.0.0.1',()=>{socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');if(head.length)target.write(head);socket.pipe(target);target.pipe(socket);});target.on('error',()=>socket.destroy());socket.on('error',()=>target.destroy());socket.on('close',()=>target.destroy());});
  let service;
  try{
    const upstreamPort=await listen(upstream),mixedPort=await freePort(),controllerPort=await freePort();
    const core=process.env.AZADNET_TEST_CORE_PATH||path.resolve(__dirname,'../resources/core',process.platform==='win32'?'mihomo.exe':'mihomo');
    service=new Service({dataDir:dir,corePath:core});await service.init();
    await service.saveSettings({mixedPort,controllerPort,routingMode:'global',mode:'rule'});
    await service.importText(`proxies:\n - name: Local fixture\n   type: http\n   server: 127.0.0.1\n   port: ${upstreamPort}\n`,'Fixture');
    await service.start();assert.equal(service.getState().status,'connected');
    const body=await new Promise((resolve,reject)=>{const req=http.get({host:'127.0.0.1',port:mixedPort,path:'http://fixture.azadnet.test/ping',headers:{Host:'fixture.azadnet.test'}},res=>{let b='';res.on('data',x=>b+=x);res.on('end',()=>resolve(b));});req.setTimeout(5000,()=>req.destroy(new Error('Proxy fixture timeout')));req.on('error',reject);});
    assert.equal(body,'azadnet-fixture');assert.ok(seen.some(x=>x.includes('fixture.azadnet.test')));
    await service.testServers();assert.ok(service.getState().servers[0].delay>=0,JSON.stringify({seen,logs:service.getLogs()}));
    const traffic=await service.traffic();assert.ok(traffic.upload>=0&&traffic.download>=0);
    await service.stop();assert.equal(service.process,null);
    await assert.rejects(new Promise((resolve,reject)=>{const socket=net.connect(mixedPort,'127.0.0.1');socket.once('connect',()=>{socket.destroy();resolve();});socket.once('error',reject);}));
  }finally{if(service)await service.shutdown();await new Promise(r=>upstream.close(r));await new Promise(r=>origin.close(r));const resolved=path.resolve(dir);if(!resolved.startsWith(root+path.sep))throw new Error('Unsafe test cleanup path');await fs.rm(resolved,{recursive:true,force:true});}
});
