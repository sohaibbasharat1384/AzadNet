'use strict';
const http=require('node:http');
const https=require('node:https');
const tls=require('node:tls');
const {performance}=require('node:perf_hooks');
const MAX_SPEED_BYTES=10*1024*1024;
const SPEED_HOST='speed.cloudflare.com';

// The request has exactly one network route: CONNECT through the active local
// mixed proxy, followed by verified TLS over that same socket. There is no
// direct DNS lookup, alternate host or retry route on proxy/TLS failure.
function downloadSpeed({proxyPort,bytes=1048576,timeoutMs=30000,signal,httpRequest=http.request,httpsRequest=https.request,tlsConnect=tls.connect,now=()=>performance.now()}={}){
  if(!Number.isInteger(proxyPort)||proxyPort<1||proxyPort>65535)return Promise.reject(new Error('Invalid local proxy port'));
  if(!Number.isInteger(bytes)||bytes<1||bytes>MAX_SPEED_BYTES)return Promise.reject(new Error('Speed test size must be between 1 byte and 10 MiB'));
  if(!Number.isInteger(timeoutMs)||timeoutMs<1||timeoutMs>30000)return Promise.reject(new Error('Speed test deadline must not exceed 30 seconds'));
  if(signal?.aborted)return Promise.reject(new Error('Speed test cancelled'));
  return new Promise((resolve,reject)=>{
    const started=now();let settled=false,connectRequest,downloadRequest,socket,secureSocket,response,agent;
    const finish=(error,result)=>{
      if(settled)return;settled=true;clearTimeout(deadline);signal?.removeEventListener('abort',abort);
      for(const item of [response,downloadRequest,connectRequest,secureSocket,socket,agent])try{item?.destroy();}catch{}
      if(error)reject(error);else resolve(result);
    };
    const abort=()=>finish(new Error('Speed test cancelled'));
    const deadline=setTimeout(()=>finish(new Error('Speed test timed out after its total deadline')),timeoutMs);
    signal?.addEventListener('abort',abort,{once:true});
    try{
      connectRequest=httpRequest({hostname:'127.0.0.1',port:proxyPort,method:'CONNECT',path:`${SPEED_HOST}:443`,agent:false,headers:{Host:`${SPEED_HOST}:443`}});
      connectRequest.once('error',e=>finish(new Error(`Speed test proxy connection failed: ${e.message}`)));
      connectRequest.once('connect',(res,tunnel,head)=>{
        socket=tunnel;if(settled){socket.destroy();return;}
        if(res.statusCode!==200){finish(new Error(`Speed test proxy rejected CONNECT (HTTP ${res.statusCode})`));return;}
        if(head?.length){finish(new Error('Speed test proxy sent unexpected tunnel data'));return;}
        try{
          agent=new https.Agent({keepAlive:false,maxSockets:1});
          agent.createConnection=()=>{
            secureSocket=tlsConnect({socket,servername:SPEED_HOST,rejectUnauthorized:true,ALPNProtocols:['http/1.1']});
            secureSocket.once('error',e=>finish(new Error(`Speed test TLS connection failed: ${e.message}`)));
            return secureSocket;
          };
          downloadRequest=httpsRequest({hostname:SPEED_HOST,port:443,method:'GET',path:`/__down?bytes=${bytes}`,agent,headers:{Host:SPEED_HOST,'Accept-Encoding':'identity','Cache-Control':'no-cache','User-Agent':'AzadNet/1.0'}},res=>{
            response=res;if(settled){res.destroy();return;}
            if(res.statusCode!==200){finish(new Error(`Speed test returned HTTP ${res.statusCode}`));return;}
            const contentLength=res.headers['content-length'];
            if(contentLength!==undefined&&(!/^\d+$/.test(String(contentLength))||Number(contentLength)!==bytes)){finish(new Error('Speed test response has an unexpected size'));return;}
            if(res.headers['content-encoding']&&res.headers['content-encoding']!=='identity'){finish(new Error('Speed test response uses unexpected compression'));return;}
            let received=0;
            res.on('data',chunk=>{received+=chunk.length;if(received>bytes||received>MAX_SPEED_BYTES)finish(new Error('Speed test response exceeded the byte limit'));});
            res.once('error',e=>finish(new Error(`Speed test download failed: ${e.message}`)));
            res.once('aborted',()=>finish(new Error('Speed test download was interrupted')));
            res.once('end',()=>{
              if(received!==bytes){finish(new Error('Speed test download ended before the expected byte count'));return;}
              const durationMs=Math.max(1,now()-started);finish(null,{bytes:received,durationMs,mbps:received*8/(durationMs*1000)});
            });
          });
          downloadRequest.once('error',e=>finish(new Error(`Speed test HTTPS request failed: ${e.message}`)));downloadRequest.end();
        }catch(e){finish(e);}
      });
      connectRequest.end();
    }catch(e){finish(e);}
  });
}
module.exports={downloadSpeed,MAX_SPEED_BYTES,SPEED_HOST};
