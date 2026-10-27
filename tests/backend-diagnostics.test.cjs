'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {EventEmitter}=require('node:events');
const {downloadSpeed,MAX_SPEED_BYTES}=require('../desktop/lib/diagnostics.cjs');
const Service=require('../desktop/lib/service.cjs');
function handle(){const value=new EventEmitter();value.destroyed=false;value.destroy=()=>{value.destroyed=true;};return value;}
function fixture({status=200,chunks=[Buffer.alloc(1024)],contentLength=1024,connectStatus=200,connectError,stall=false,tlsError}={}){
  const seen={connect:[],https:[],tls:[],handles:[]};
  const socket=handle();seen.handles.push(socket);
  const httpRequest=opts=>{seen.connect.push(opts);const req=handle();seen.handles.push(req);req.end=()=>setImmediate(()=>{if(connectError)req.emit('error',new Error(connectError));else if(!stall)req.emit('connect',{statusCode:connectStatus},socket,Buffer.alloc(0));});return req;};
  const tlsConnect=opts=>{seen.tls.push(opts);const secure=handle();seen.handles.push(secure);if(tlsError)setImmediate(()=>secure.emit('error',new Error(tlsError)));return secure;};
  const httpsRequest=(opts,callback)=>{seen.https.push(opts);opts.agent.createConnection();const req=handle();seen.handles.push(req);req.end=()=>setImmediate(()=>{
    const res=handle();res.statusCode=status;res.headers=contentLength===null?{}:{'content-length':String(contentLength)};seen.handles.push(res);callback(res);
    for(const b of chunks)res.emit('data',b);res.emit('end');
  });return req;};
  let clock=0;return {seen,httpRequest,httpsRequest,tlsConnect,now:()=>clock++?1000:0};
}
test('speed request connects only to active loopback proxy and verifies fixed-host TLS over its socket',async()=>{
  const f=fixture(),result=await downloadSpeed({proxyPort:2080,bytes:1024,...f});assert.deepEqual(result,{bytes:1024,durationMs:1000,mbps:0.008192});
  assert.equal(f.seen.connect.length,1);assert.equal(f.seen.connect[0].hostname,'127.0.0.1');assert.equal(f.seen.connect[0].port,2080);assert.equal(f.seen.connect[0].method,'CONNECT');assert.equal(f.seen.connect[0].path,'speed.cloudflare.com:443');
  assert.equal(f.seen.https[0].hostname,'speed.cloudflare.com');assert.equal(f.seen.https[0].path,'/__down?bytes=1024');assert.equal(f.seen.tls[0].rejectUnauthorized,true);assert.equal(f.seen.tls[0].servername,'speed.cloudflare.com');assert.equal(f.seen.tls[0].socket,f.seen.handles[0]);assert.ok(f.seen.handles.every(h=>h.destroyed));
});
test('proxy rejection and failure never fall back to direct HTTPS',async()=>{
  for(const opts of [{connectStatus:403},{connectError:'refused'}]){const f=fixture(opts);await assert.rejects(downloadSpeed({proxyPort:2080,bytes:1024,...f}),/proxy/);assert.equal(f.seen.https.length,0);assert.equal(f.seen.tls.length,0);assert.equal(f.seen.connect.length,1);}
});
test('speed test validates byte/deadline caps before creating requests',async()=>{
  const f=fixture();for(const bytes of [0,-1,1.5,MAX_SPEED_BYTES+1,NaN])await assert.rejects(downloadSpeed({proxyPort:2080,bytes,...f}),/size/);
  await assert.rejects(downloadSpeed({proxyPort:2080,timeoutMs:30001,...f}),/deadline/);await assert.rejects(downloadSpeed({proxyPort:0,...f}),/port/);assert.equal(f.seen.connect.length,0);
});
test('response size, truncation and redirect failures reject without accepting misleading throughput',async()=>{
  for(const opts of [{contentLength:2048},{contentLength:null,chunks:[Buffer.alloc(1025)]},{contentLength:null,chunks:[Buffer.alloc(100)]},{status:302}]){const f=fixture(opts);await assert.rejects(downloadSpeed({proxyPort:2080,bytes:1024,...f}),/size|byte|HTTP/);assert.equal(f.seen.connect.length,1);assert.equal(f.seen.https.length,1);}
});
test('one total deadline and caller cancellation destroy the proxy request',async()=>{
  const f=fixture({stall:true});await assert.rejects(downloadSpeed({proxyPort:2080,bytes:1024,timeoutMs:15,...f}),/total deadline/);assert.equal(f.seen.handles[1].destroyed,true);
  const controller=new AbortController(),g=fixture({stall:true}),pending=downloadSpeed({proxyPort:2080,bytes:1024,signal:controller.signal,...g});controller.abort();await assert.rejects(pending,/cancelled/);assert.equal(g.seen.handles[1].destroyed,true);
});
test('speed service method requires an active connection and excludes concurrent diagnostics',async()=>{
  const svc=new Service({dataDir:'.unused-test-data'});await assert.rejects(svc.speedTest(),/Connect/);svc.status='connected';svc.controller={};svc.testing=true;await assert.rejects(svc.speedTest(),/operation/);svc.testing=false;svc.speedTesting=true;await assert.rejects(svc.speedTest(),/operation/);await assert.rejects(svc.selectServer('anything'),/speed test/);await assert.rejects(svc.testServers(),/speed test/);
});
