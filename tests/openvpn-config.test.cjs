'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {parseOpenVPNConfig,MAX_OPENVPN_BYTES}=require('../desktop/lib/openvpn-config.cjs');
const auth={username:'local-fixture-user',password:'synthetic-fixture-password'};
const config=`client\ndev tun\nproto tcp-client\nremote node.example 443\nauth-user-pass\nauth SHA512\ncipher AES-256-GCM\ndata-ciphers AES-256-GCM:AES-128-GCM\nremote-cert-tls server\nverify-x509-name "node-identity" name\nkey-direction 1\nping 10\nping-restart 60\n<ca>\n-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n</ca>\n<tls-auth>\n-----BEGIN OpenVPN Static key V1-----\n${'01'.repeat(256)}\n-----END OpenVPN Static key V1-----\n</tls-auth>\n`;
test('OpenVPN conversion preserves transport, authentication, inline crypto and peer identity constraints',()=>{
  const {proxies:[p]}=parseOpenVPNConfig(config,{name:'Windscribe · Test',auth});
  assert.equal(p.type,'openvpn');assert.equal(p.proto,'tcp');assert.equal(p.port,443);assert.equal(p.auth,'SHA512');assert.equal(p.cipher,'AES-256-GCM');assert.equal(p.username,auth.username);assert.equal(p.password,auth.password);assert.equal(p['verify-x509-name'],'node-identity');assert.equal(p['verify-x509-name-type'],'name');assert.ok(p.ca.includes('CERTIFICATE'));assert.ok(p['tls-auth'].includes('Static key'));assert.equal(p['ping-restart'],60);
});
test('multiple remotes preserve individual protocol and port without losing node identity',()=>{
  const text=config.replace('remote node.example 443','remote node.example 443\nremote second.example 1194 udp');
  const {proxies}=parseOpenVPNConfig(text,{name:'Group',auth});assert.equal(proxies.length,2);assert.equal(proxies[1].proto,'udp');assert.equal(proxies[1].port,1194);assert.equal(proxies[0].name,'Group #1');
});

test('OpenVPN legacy cipher negotiation alias and data-only CLIENT_CERT marker are accepted',()=>{
  const text=config.replace('data-ciphers ','ncp-ciphers ')+'\nsetenv CLIENT_CERT 0\n';const {proxies:[p]}=parseOpenVPNConfig(text,{auth});assert.deepEqual(p['data-ciphers'],['AES-256-GCM','AES-128-GCM']);
  assert.throws(()=>parseOpenVPNConfig(config+'\nsetenv dangerous value',{auth}),/Unsupported directive/);
});
test('file references, scripts and certificate verification downgrade are rejected',()=>{
  for(const [text,pattern]of [
    [config+'\nup "echo not-executed"',/Unsupported directive/],
    [config+'\nplugin auth.dll',/Unsupported directive/],
    [config.replace('auth-user-pass','auth-user-pass password.txt'),/External credential/],
    [config+'\nca other-file.pem',/Unsupported directive/],
    [config.replace('node-identity" name','node-identity" subject'),/identity checks/],
    [config.replace('remote-cert-tls server','remote-cert-tls client'),/certificate validation/],
    [config.replace('dev tun','dev tap'),/dev tun/],
  ])assert.throws(()=>parseOpenVPNConfig(text,{auth}),pattern);
});
test('missing credentials and malformed profile errors do not reveal sensitive data',()=>{
  assert.throws(()=>parseOpenVPNConfig(config),/username/);
  for(const value of [auth.password+'\ninvalid','']){let caught;try{parseOpenVPNConfig(config,{auth:{...auth,password:value}});}catch(e){caught=e;}assert.ok(caught);assert.equal(caught.message.includes(auth.password),false);}
  assert.throws(()=>parseOpenVPNConfig('x'.repeat(MAX_OPENVPN_BYTES+1)),/256 KiB/);
  assert.throws(()=>parseOpenVPNConfig(config.replace('</ca>',''),{auth}),/Unterminated/);
});
test('profile-specific DNS stays inside the outbound and OS routes are reported rather than executed',()=>{
  const {proxies:[p],warnings}=parseOpenVPNConfig(config+'\ndhcp-option DNS 10.9.0.1\nredirect-gateway def1\nblock-outside-dns\n',{auth});assert.deepEqual(p.dns,['10.9.0.1']);assert.equal(p['remote-dns-resolve'],true);assert.equal(warnings.length,2);
});
