'use strict';
const http=require('node:http');
class Controller{
  constructor(port,secret,{delayUrl='https://cp.cloudflare.com/generate_204'}={}){this.port=port;this.secret=secret;this.delayUrl=delayUrl;}
  request(method,path,body,timeout=6000){
    return new Promise((resolve,reject)=>{
      const data=body===undefined?null:JSON.stringify(body);
      const req=http.request({hostname:'127.0.0.1',port:this.port,path,method,headers:{Authorization:`Bearer ${this.secret}`,...(data?{'Content-Type':'application/json','Content-Length':Buffer.byteLength(data)}:{})}},res=>{
        let bytes=0,chunks=[];res.on('data',b=>{bytes+=b.length;if(bytes>4*1024*1024){res.destroy(new Error('Controller response too large'));return;}chunks.push(b);});res.on('error',reject);res.on('end',()=>{
          const text=Buffer.concat(chunks).toString();if(res.statusCode<200||res.statusCode>=300){reject(new Error(`Core controller returned HTTP ${res.statusCode}`));return;}
          try{resolve(text?JSON.parse(text):null);}catch{reject(new Error('Invalid controller response'));}
        });
      });
      req.setTimeout(timeout,()=>req.destroy(new Error('Core controller timed out')));req.on('error',reject);if(data)req.write(data);req.end();
    });
  }
  version(){return this.request('GET','/version');}
  configs(){return this.request('GET','/configs');}
  select(name,group='AZADNET'){return this.request('PUT',`/proxies/${encodeURIComponent(group)}`,{name});}
  delay(name,{timeout=3000}={}){return this.request('GET',`/proxies/${encodeURIComponent(name)}/delay?timeout=${timeout}&url=${encodeURIComponent(this.delayUrl)}`,undefined,timeout+1500);}
  traffic(){return this.request('GET','/connections').then(x=>({upload:x.uploadTotal||0,download:x.downloadTotal||0,connections:x.connections?.length||0}));}
}
module.exports={Controller};
