'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const os=require('node:os');
const path=require('node:path');
const http=require('node:http');
const {EventEmitter}=require('node:events');
const {PassThrough}=require('node:stream');
const {parse}=require('yaml');
const Service=require('../desktop/lib/service.cjs');
const freePort=async()=>{const s=http.createServer();await new Promise(r=>s.listen(0,'127.0.0.1',r));const p=s.address().port;await new Promise(r=>s.close(r));return p;};

async function fixture({tunEnabled=false,delays={Dead:null,Good:25}}={}){
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),'azadnet-routing-'));
  let server,kills=0;const configs=[],selections=[];
  const spawnProcess=(_exe,args)=>{
    const child=new EventEmitter();child.stdout=new PassThrough();child.stderr=new PassThrough();child.exitCode=null;
    child.kill=()=>{kills++;server?.close();child.exitCode=0;setImmediate(()=>child.emit('exit',0));return true;};
    if(args.includes('-t'))setImmediate(()=>{child.exitCode=0;child.emit('exit',0);});
    else setImmediate(async()=>{
      const cfg=parse(await fs.readFile(path.join(dir,'runtime.yaml'),'utf8'));configs.push(cfg);
      server=http.createServer((req,res)=>{
        if(req.headers.authorization!==`Bearer ${cfg.secret}`){res.writeHead(403);res.end();return;}
        if(req.url==='/version')res.end('{"version":"routing-fixture"}');
        else if(req.url==='/configs')res.end(JSON.stringify({tun:{enable:tunEnabled,'auto-route':true}}));
        else if(req.url.includes('/delay?')){
          const name=decodeURIComponent(req.url.split('/')[2]);
          if(!delays[name]){res.writeHead(504);res.end('{}');}else res.end(JSON.stringify({delay:delays[name]}));
        }else if(req.method==='PUT'){
          let body='';req.on('data',b=>body+=b);req.on('end',()=>{selections.push(JSON.parse(body).name);res.writeHead(204);res.end();});
        }else{res.writeHead(404);res.end();}
      });server.listen(cfg['external-controller'].split(':').at(-1),'127.0.0.1');
      if(cfg.tun&&!tunEnabled)child.stdout.write('Start TUN listening error: configure tun interface: Access is denied.\n');
    });
    return child;
  };
  const service=new Service({dataDir:dir,corePath:process.execPath,spawnProcess});await service.init();
  await service.saveSettings({mixedPort:await freePort(),controllerPort:await freePort(),tun:true});
  await service.importText('proxies:\n - {name: Dead, type: http, server: dead.example, port: 8080}\n - {name: Good, type: http, server: good.example, port: 8080}');
  return {service,configs,selections,get kills(){return kills;},async close(){await service.shutdown();if(server?.listening)await new Promise(r=>server.close(r));await fs.rm(dir,{recursive:true,force:true});}};
}

test('controller readiness cannot claim a VPN connection after silent TUN access denial',async()=>{
  const f=await fixture();try{
    await assert.rejects(f.service.start(),/TUN/);assert.equal(f.service.status,'disconnected');assert.equal(f.service.activeTun,false);assert.equal(f.service.process,null);assert.equal(f.kills,1);assert.equal(f.selections.length,0);
    assert.ok(f.service.getLogs().some(x=>x.message.includes('Access is denied')));
  }finally{await f.close();}
});

test('server test bypasses failed TUN, selects a responding server and preserves requested VPN mode',async()=>{
  const f=await fixture();try{
    await f.service.testServers();assert.equal(f.configs[0].tun,undefined);assert.equal(f.service.settings.tun,true);assert.equal(f.service.status,'disconnected');assert.equal(f.service.selectedServer,'Good');assert.equal(f.service.delays.get('Dead'),-1);
    const saved=JSON.parse(await fs.readFile(f.service.file,'utf8'));assert.equal(saved.selectedServer,'Good');assert.equal(saved.settings.tun,true);
  }finally{await f.close();}
});

test('enabled TUN alone does not mark an unresponsive selected server connected',async()=>{
  const f=await fixture({tunEnabled:true});try{
    await assert.rejects(f.service.start(),/سرور/);assert.equal(f.service.status,'disconnected');assert.equal(f.service.process,null);assert.equal(f.service.activeTun,false);
    await f.service.selectServer('Good');await f.service.start();assert.equal(f.service.status,'connected');assert.equal(f.service.activeTun,true);
    await assert.rejects(f.service.selectServer('Dead'),/سرور/);assert.equal(f.service.selectedServer,'Good');assert.equal(f.selections.at(-1),'Good');
    await f.service.stop();assert.equal(f.service.activeTun,false);
  }finally{await f.close();}
});

test('failed server sweep reports failure and releases its temporary listener',async()=>{
  const f=await fixture({delays:{}});try{
    await assert.rejects(f.service.testServers(),/هیچ سروری/);assert.equal(f.service.status,'disconnected');assert.equal(f.service.process,null);assert.equal(f.service.testing,false);assert.equal(f.service.selectedServer,'Dead');
  }finally{await f.close();}
});
