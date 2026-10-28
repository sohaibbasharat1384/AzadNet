'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const net=require('node:net');
const path=require('node:path');
const {spawn}=require('node:child_process');
const {WindscribeRuntime,protocolOf}=require('../desktop/lib/windscribe-runtime.cjs');
const normal={name:'Normal',type:'http',server:'normal.example',port:80};
test('test-only preparation excludes native and wrapped profiles without starting external processes',async()=>{
  let starts=0;const runtime=new WindscribeRuntime({dataDir:'.',corePath:process.execPath,nativeIKE:{async start(){starts++;}}});
  const profiles=[normal,{name:'IKE',type:'ikev2'},{name:'Stealth',type:'openvpn','windscribe-mode':'stealth'},{name:'WS',type:'openvpn','windscribe-mode':'wstunnel'}];
  for(const selected of profiles){const result=await runtime.prepare(selected,profiles,{testOnly:true});assert.deepEqual(result.proxies,[normal]);assert.equal(result.nativeVpn,false);}assert.equal(starts,0);
});
test('native preparation exposes a direct local outbound only after the system connection succeeds',async()=>{
  let connected=false;const runtime=new WindscribeRuntime({dataDir:'.',corePath:process.execPath,nativeIKE:{async start(){connected=true;}}});
  const p={name:'IKE',type:'ikev2'};const result=await runtime.prepare(p,[p,normal]);assert.equal(connected,true);assert.equal(result.nativeVpn,true);assert.deepEqual(result.proxies,[normal,{name:'IKE',type:'direct'}]);assert.equal(protocolOf(p),'ikev2');
});
test('packaged official helper transports real bytes over TLS and WebSocket and closes its listener',{skip:process.env.AZADNET_TEST_REAL_TUNNEL!=='1',timeout:30000},async()=>{
  const executable=process.env.AZADNET_ECHO_FIXTURE;if(!executable)throw Error('Build tests/fixtures/windscribe-echo.go and set AZADNET_ECHO_FIXTURE');
  const fixture=spawn(executable,[],{windowsHide:true,stdio:['ignore','pipe','pipe']});
  const endpoints=await new Promise((resolve,reject)=>{let out='';const timer=setTimeout(()=>reject(Error('fixture startup timed out')),5000);fixture.once('error',reject);fixture.stdout.on('data',b=>{out+=b;if(out.includes('\n')){clearTimeout(timer);try{resolve(JSON.parse(out.trim()));}catch(e){reject(e);}}});});
  const corePath=path.resolve(__dirname,'../resources/core/mihomo.exe');
  const logs=[];const runtime=new WindscribeRuntime({dataDir:'.',corePath,log:line=>logs.push(line),nativeIKE:{async stop(){},async available(){return true;}}});
  try{
    for(const mode of ['stealth','wstunnel']){
      const port=Number(endpoints[mode].split(':').at(-1));const p={name:mode,type:'openvpn',server:'inner.example',port:443,proto:'tcp',ca:'inner-ca','verify-x509-name':'inner-identity','verify-x509-name-type':'name','windscribe-mode':mode,'outer-server':'127.0.0.1','outer-port':port,'outer-sni':'fixture.test'};
      const result=await runtime.prepare(p,[p,normal]),outbound=result.proxies.at(-1);
      assert.equal(outbound.server,'127.0.0.1');assert.equal(outbound.ca,'inner-ca');assert.equal(outbound['verify-x509-name'],'inner-identity');assert.equal(outbound['windscribe-mode'],undefined);assert.deepEqual(result.routeExcludes,['127.0.0.1/32']);
      const payload=Buffer.from('local fixture '+mode+' '+('A'.repeat(2000)));
      const echoed=await new Promise((resolve,reject)=>{const socket=net.connect(outbound.port,'127.0.0.1',()=>socket.write(payload));let response=Buffer.alloc(0);socket.setTimeout(6000,()=>socket.destroy(Error('echo timeout')));socket.on('data',b=>{response=Buffer.concat([response,b]);if(response.length>=payload.length){socket.destroy();resolve(response);}});socket.once('error',e=>reject(new Error(mode+': '+e.message+'\n'+logs.join('\n'))));});
      assert.deepEqual(echoed,payload);await runtime.stop();
      await assert.rejects(new Promise((resolve,reject)=>{const socket=net.connect(outbound.port,'127.0.0.1');socket.once('connect',()=>{socket.destroy();resolve();});socket.once('error',reject);}));
    }
  }finally{await runtime.stop();fixture.kill();}
});
