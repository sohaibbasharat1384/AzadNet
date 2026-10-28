'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const os=require('node:os');
const path=require('node:path');
const {EventEmitter}=require('node:events');
const {PassThrough}=require('node:stream');
const {NativeIKEv2,runPrivate}=require('../desktop/lib/native-ikev2.cjs');
const profile={server:'ike.example.test',port:500,username:'fixture-user',password:'fixture-only-secret'};
async function fixture(run){const dir=await fs.mkdtemp(path.join(os.tmpdir(),'azadnet-ike-test-'));return {dir,native:new NativeIKEv2({dataDir:dir,platform:'win32',run}),async close(){assert.ok(dir.startsWith(os.tmpdir()+path.sep));await fs.rm(dir,{recursive:true,force:true});}};}
test('native ownership survives restart, contains no credentials, and cleans only its own connection',async()=>{
  const calls=[];const run=async(command,args,input)=>{calls.push(structuredClone(input));assert.equal(args.join(' ').includes(profile.password),false);return input.operation==='create'?{created:true}:input.operation==='stop'?{stopped:true}:{connected:true};};
  const f=await fixture(run);try{
    await f.native.start(profile);const receipt=JSON.parse(await fs.readFile(f.native.file,'utf8'));
    assert.deepEqual(Object.keys(receipt).sort(),['name','platform','uuid']);assert.equal(calls[0].password,undefined);assert.equal(calls[1].password,profile.password);
    const restart=new NativeIKEv2({dataDir:f.dir,platform:'win32',run});await restart.stop();assert.equal(calls.at(-1).name,receipt.name);assert.equal(calls.at(-1).password,undefined);await assert.rejects(fs.access(restart.file),{code:'ENOENT'});
  }finally{await f.close();}
});
test('failed native disconnect preserves the recovery receipt and can be retried',async()=>{
  let allowStop=false;const f=await fixture(async(_c,_a,input)=>input.operation==='create'?{created:true}:input.operation==='stop'?{stopped:allowStop}:{connected:true});
  try{await f.native.start(profile);await assert.rejects(f.native.stop(),/still active/);await fs.access(f.native.file);assert.equal(f.native.active,true);allowStop=true;await f.native.stop();assert.equal(f.native.active,false);}finally{await f.close();}
});
test('tampered ownership cannot target a different VPN profile',async()=>{
  let calls=0;const f=await fixture(async()=>{calls++;});try{
    await fs.writeFile(f.native.file,JSON.stringify({name:'AzadNet-Windscribe-'+'0'.repeat(32),uuid:'11111111-1111-1111-1111-111111111111',platform:'win32'}));await assert.rejects(f.native.stop(),/ownership/);assert.equal(calls,0);
  }finally{await f.close();}
});
test('private helper input travels over stdin and backend errors cannot echo secrets',async()=>{
  let captured;
  const spawnProcess=(command,args,options)=>{assert.equal(args.includes(profile.password),false);assert.equal(options.shell,false);const child=new EventEmitter();child.stdin=new PassThrough();child.stdout=new PassThrough();child.stderr=new PassThrough();child.kill=()=>{};let input='';child.stdin.on('data',b=>input+=b);child.stdin.on('finish',()=>{captured=JSON.parse(input);child.stderr.write(profile.password);child.stdout.end(JSON.stringify({error:profile.password,code:691}));setImmediate(()=>child.emit('close',0));});return child;};
  await assert.rejects(runPrivate('fixed-helper',['fixed-script'],profile,{spawnProcess}),error=>error.message==='IKEv2 system operation failed (691)');assert.deepEqual(captured,profile);
});
