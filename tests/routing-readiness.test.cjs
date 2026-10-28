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

async function fixture({tunEnabled=false,delays={Dead:null,Good:25},windscribeRuntime}={}){
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
  const service=new Service({dataDir:dir,corePath:process.execPath,spawnProcess,windscribeRuntime});await service.init();
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

test('native IKEv2 connection disables Mihomo TUN and requires confirmed OS cleanup',async()=>{
  let stopFails=false,stops=0;
  const windscribeRuntime={async recover(){},async prepare(p){return {proxies:[{name:p.name,type:'direct'}],nativeVpn:true,routeExcludes:[]};},native:{async status(){return {connected:true};}},async stop(){stops++;if(stopFails)throw Error('OS disconnect failure');}};
  const f=await fixture({windscribeRuntime});try{
    f.service.subscriptions=[{id:'native',source:'windscribe',name:'Native',proxies:[{name:'Good',type:'ikev2',server:'ike.example',port:500,username:'fixture-user',password:'fixture-secret'}]}];f.service.selectedServer='Good';
    await f.service.start();assert.equal(f.service.nativeVpn,true);assert.equal(f.service.activeTun,false);assert.equal(f.configs[0].tun,undefined);assert.equal(f.service.settings.tun,true);assert.equal(f.configs[0].proxies[0].type,'direct');
    stopFails=true;await assert.rejects(f.service.stop(),/IKEv2/);assert.equal(f.service.status,'cleanup-required');await assert.rejects(f.service.start(),/IKEv2/);
    stopFails=false;await f.service.stop();assert.equal(f.service.status,'disconnected');assert.equal(f.service.nativeVpn,false);assert.equal(stops,2);
  }finally{stopFails=false;await f.close();}
});

test('bulk tests skip external Windscribe transports without activating OS VPN or helpers',async()=>{
  const f=await fixture();try{
    f.service.subscriptions.push({id:'special',source:'windscribe',name:'Special',proxies:[{name:'IKE',type:'ikev2',server:'ike.example',port:500,username:'fixture-user',password:'fixture-secret'}]});
    const result=await f.service.testServers();assert.equal(result.testSummary.skipped,1);assert.equal(result.testSummary.tested,2);assert.equal(f.configs[0].proxies.some(p=>p.type==='ikev2'),false);assert.equal(f.service.nativeVpn,false);
    await assert.rejects(f.service.testServers({source:'windscribe'}),/پروفایل/);assert.equal(f.configs.length,1);
  }finally{await f.close();}
});

test('startup recovery failure blocks new connections and shutdown retries owned cleanup',async()=>{
  let stops=0;const runtime={async recover(){throw Error('OS unavailable');},async stop(){if(++stops===1)throw Error('temporary failure');}};
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),'azadnet-recovery-'));const service=new Service({dataDir:dir,windscribeRuntime:runtime});
  try{await service.init();assert.equal(service.status,'cleanup-required');await assert.rejects(service.start(),/IKEv2/);await service.shutdown();assert.equal(stops,2);assert.equal(service.status,'disconnected');}finally{assert.ok(dir.startsWith(os.tmpdir()+path.sep));await fs.rm(dir,{recursive:true,force:true});}
});
