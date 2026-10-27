'use strict';
const net = require('node:net');

// Recovered from W2.d/W2.f, L4.g0/h0 and C0667s3 in the supplied APK.
const FRAGMENT_PRESETS = [
  ['13-23', '1-5', '7-17', '1-4'], ['10-15', '1-2', '6-12', '1'],
  ['10-20', '1-6', '6-14', '2-4'], ['15-30', '1-2', '10-20', '1-2'],
  ['8-14', '1-3', '5-10', '0-1'], ['12-20', '1-3', '2-6', '2-4'],
].map(([hello, packets, lengths, delays]) => ({tcp: [
  {type: 'fragment', settings: {packets: 'tlshello', lengths: [hello], delays: ['0'], maxSplit: '256'}},
  {type: 'fragment', settings: {packets, lengths: [lengths], delays: [delays], maxSplit: '256'}},
]}));
const ADVANCED_DEFAULTS = Object.freeze({
  routingMode: 'iran', iranRemoteRules: false,
  fragmentsEnabled: false, fragmentJson: JSON.stringify(FRAGMENT_PRESETS[0], null, 2),
  fragmentAlpn: '', fragmentCipherSuites: '', frontingEndpoints: Object.freeze([]),
  lanPasswordRequired: true, lanUsername: 'whitedns', lanPassword: '',
  amneziaNoiseEnabled: false, noiseCount: 5, noiseMinSize: 50, noiseMaxSize: 100,
});
const PRIVATE_RANGES = ['127.0.0.0/8','10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','100.64.0.0/10'];
const IRAN_RULE_URL = 'https://github.com/ygbkm/clash-rules-iran/releases/latest/download/rules.txt';
const own = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);
const object = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const clone = v => JSON.parse(JSON.stringify(v));

function range(value, label, max = 2147483647) {
  if (!['number','string'].includes(typeof value) || (typeof value === 'number' && !Number.isSafeInteger(value))) throw new Error(`${label}: expected a nonnegative number or range`);
  const text = String(value).trim();
  if (!/^\d+(?:-\d+)?$/.test(text)) throw new Error(`${label}: expected a nonnegative number or range`);
  const values = text.split('-').map(Number);
  if (values.some(n => !Number.isSafeInteger(n) || n > max)) throw new Error(`${label}: value exceeds ${max}`);
  return {text, min: Math.min(...values), max: Math.max(...values)};
}
function listRange(value, label, max) {
  const values = Array.isArray(value) ? value : [value];
  if (!values.length || values.length > 256) throw new Error(`${label}: expected 1–256 values`);
  return values.map(v => range(v, label, max));
}
function oneKey(settings, keys, required) {
  const found = keys.filter(k => own(settings, k));
  if (found.length > 1 || (required && found.length !== 1)) throw new Error(`Use ${required ? 'exactly' : 'at most'} one of ${keys.join(', ')}`);
  return found[0];
}
function parseFragments(raw) {
  if (typeof raw !== 'string' || Buffer.byteLength(raw) > 65536) throw new Error('Fragment JSON must be text of at most 64 KiB');
  let parsed;
  try { parsed = JSON.parse(raw); } catch { throw new Error('Fragment JSON is invalid'); }
  if (!object(parsed) || !Array.isArray(parsed.tcp) || parsed.tcp.length < 1 || parsed.tcp.length > 8) throw new Error('Fragment JSON must contain a tcp list with 1–8 stages');
  return parsed.tcp.map((stage, index) => {
    if (!object(stage) || stage.type !== 'fragment' || !object(stage.settings)) throw new Error(`tcp[${index}] must be a fragment with settings`);
    const s = stage.settings;
    const allowed = new Set(['packets','length','lengths','delay','delays','interval','maxSplit','max-split']);
    if (Object.keys(s).some(k => !allowed.has(k))) throw new Error(`tcp[${index}].settings contains an unsupported field`);
    const out = {};
    if (own(s, 'packets')) {
      if (typeof s.packets !== 'string' && typeof s.packets !== 'number') throw new Error('packets must be tlshello or a positive number/range');
      const p = String(s.packets).trim();
      if (p && p.toLowerCase() !== 'tlshello' && range(p, 'packets').min < 1) throw new Error('packets must be tlshello or a positive number/range');
      if (p) out.packets = p;
    }
    const lengthKey = oneKey(s, ['length','lengths'], true);
    const lengths = listRange(s[lengthKey], lengthKey);
    if (lengths.at(-1).min < 1) throw new Error('The final fragment length must start above zero');
    if (lengthKey === 'length' && lengths.length !== 1) throw new Error('Use lengths for multiple fragment lengths');
    out[lengthKey] = lengthKey.endsWith('s') ? lengths.map(r => r.text) : lengths[0].text;
    const delayKey = oneKey(s, ['delay','delays','interval'], false);
    if (delayKey) {
      const delays = listRange(s[delayKey], delayKey, 1000);
      if (!delayKey.endsWith('s') && delays.length !== 1) throw new Error('Use delays for multiple fragment delays');
      out[delayKey] = delayKey.endsWith('s') ? delays.map(r => r.text) : delays[0].text;
    }
    const maxKey = oneKey(s, ['maxSplit','max-split'], false);
    if (maxKey) {
      const split = range(s[maxKey], maxKey, 256);
      if (split.min === 0 && split.max === 0) out[maxKey] = '256';
      else if (split.min < 1) throw new Error(`${maxKey} must be between 1 and 256`);
      else out[maxKey] = split.text;
    }
    return out;
  });
}

function parseFrontingEndpoint(value) {
  if (typeof value !== 'string' || value.length > 128 || value.trim() !== value || !value) throw new Error('IP fronting requires IP[:port]');
  let ip = value, port;
  if (value.startsWith('[')) {
    const match = /^\[([^\]]+)\](?::([0-9]+))?$/.exec(value);
    if (!match || net.isIP(match[1]) !== 6) throw new Error('Invalid IPv6 fronting endpoint');
    ip = match[1]; if (match[2]) port = Number(match[2]);
  } else if (!net.isIP(value)) {
    const match = /^([^:]+):([0-9]+)$/.exec(value);
    if (!match || net.isIP(match[1]) !== 4) throw new Error('IP fronting requires a literal IPv4 or IPv6 address');
    ip = match[1]; port = Number(match[2]);
  }
  if (!net.isIP(ip) || ip.includes('%')) throw new Error('Invalid fronting IP');
  if (port !== undefined && (!Number.isInteger(port) || port < 1 || port > 65535)) throw new Error('Fronting port must be between 1 and 65535');
  return {ip, port};
}
function validateAdvanced(patch, current = ADVANCED_DEFAULTS) {
  if (!object(patch)) throw new Error('Advanced settings must be an object');
  const settings = {...ADVANCED_DEFAULTS, ...current};
  for (const [key, value] of Object.entries(patch)) {
    if (!own(ADVANCED_DEFAULTS, key)) throw new Error(`Unknown advanced setting: ${key}`);
    if (['iranRemoteRules','fragmentsEnabled','lanPasswordRequired','amneziaNoiseEnabled'].includes(key)) {
      if (typeof value !== 'boolean') throw new Error(`${key} must be boolean`);
    } else if (key === 'routingMode') {
      if (!['iran','global','subscription'].includes(value)) throw new Error('Invalid routing mode');
    } else if (key === 'frontingEndpoints') {
      if (!Array.isArray(value) || value.length > 5) throw new Error('IP fronting accepts at most five endpoints');
      value.forEach(parseFrontingEndpoint);
    } else if (['noiseCount','noiseMinSize','noiseMaxSize'].includes(key)) {
      if (!Number.isInteger(value) || value < 0 || value > 65535) throw new Error(`${key} must be an integer between 0 and 65535`);
    } else {
      if (typeof value !== 'string') throw new Error(`${key} must be text`);
      if (key === 'fragmentJson') parseFragments(value);
      if (key === 'fragmentAlpn' && (value.length > 512 || value.split(',').some(v => /[\s\x00-\x1f]/.test(v.trim())))) throw new Error('ALPN must be comma-separated protocol names');
      if (key === 'fragmentCipherSuites' && (value.length > 2048 || !/^[A-Z0-9_:]*$/.test(value))) throw new Error('Cipher suites must be colon-separated TLS names');
      if (key === 'lanUsername' && (!/^[A-Za-z0-9_.-]{1,64}$/.test(value))) throw new Error('LAN username must contain 1–64 letters, digits, dot, underscore or hyphen');
      if (key === 'lanPassword' && (value.length > 128 || /[:\r\n\x00]/.test(value))) throw new Error('LAN password cannot contain colon, newline or NUL');
    }
    settings[key] = Array.isArray(value) ? [...value] : value;
  }
  if (settings.noiseMinSize > settings.noiseMaxSize) throw new Error('Noise minimum size cannot exceed maximum size');
  // Saved settings can be loaded without fragment activation; malformed saved JSON
  // must still fail before generating a core configuration.
  parseFragments(settings.fragmentJson);
  return settings;
}

function applyAdvanced(config, settings, opts = {}) {
  const source = settings || {};
  const patch = Object.fromEntries(Object.keys(ADVANCED_DEFAULTS).filter(k => own(source, k)).map(k => [k, source[k]]));
  const s = validateAdvanced(patch);
  if (s.fragmentsEnabled && opts.fragmentsSupported !== true) throw new Error('The desktop core does not support the Android fragments extension. Disable fragmentation to connect; a compatible custom core is required.');
  const out = clone(config);
  const fragments = s.fragmentsEnabled ? parseFragments(s.fragmentJson) : null;
  const endpoints = s.frontingEndpoints.map(parseFrontingEndpoint);
  const endpointIndex = opts.frontingIndex === undefined ? 0 : opts.frontingIndex;
  if (!Number.isInteger(endpointIndex) || endpointIndex < 0 || (endpoints.length && endpointIndex >= endpoints.length)) throw new Error('Invalid fronting endpoint index');
  const endpoint = endpoints[endpointIndex];
  for (const proxy of out.proxies || []) {
    const frontingEligible = ['vless','vmess','trojan','socks5','http','anytls'].includes(String(proxy.type).toLowerCase()) && (proxy.tls || proxy['reality-opts'] || ['trojan','anytls'].includes(String(proxy.type).toLowerCase()));
    if (endpoint && frontingEligible) {
      // Keep TLS SNI and transport Host intact, matching L4.h0. Selection/scanning
      // between multiple endpoints belongs to the runtime caller.
      proxy.server = endpoint.ip;
      if (endpoint.port !== undefined) proxy.port = endpoint.port;
    }
    if (fragments) {
      proxy.fragments = clone(fragments);
      if (String(proxy.type).toLowerCase() === 'vless') {
        if (proxy['reality-opts'] && (!proxy['client-fingerprint'] || ['none','unsafe'].includes(String(proxy['client-fingerprint']).toLowerCase()))) proxy['client-fingerprint'] = 'chrome';
        if (s.fragmentAlpn.trim() && !own(proxy, 'alpn') && !['grpc','h2','xhttp'].includes(String(proxy.network || '').toLowerCase())) proxy.alpn = s.fragmentAlpn.split(',').map(x => x.trim()).filter(Boolean);
        if (s.fragmentCipherSuites && !own(proxy, 'cipher-suites')) proxy['cipher-suites'] = s.fragmentCipherSuites;
      }
    }
    if (s.amneziaNoiseEnabled && String(proxy.type).toLowerCase() === 'wireguard') proxy['amnezia-wg-option'] = {...proxy['amnezia-wg-option'], jc:s.noiseCount,jmin:s.noiseMinSize,jmax:s.noiseMaxSize};
    // The public desktop core removed global-client-fingerprint. Preserve the
    // Android Chrome default at the supported per-proxy location instead.
    if ((proxy.tls || proxy['reality-opts'] || ['trojan','hysteria2','tuic'].includes(String(proxy.type).toLowerCase())) && !own(proxy,'client-fingerprint')) proxy['client-fingerprint'] = 'chrome';
  }
  delete out['global-client-fingerprint'];
  out['geo-auto-update'] = false;
  out['find-process-mode'] = 'off';
  if (out.dns) {
    out.dns.listen ||= '127.0.0.1:1053';
    const bootstrap = source.dnsTransport === 'dot' ? ['tls://1.1.1.1:853','tls://8.8.8.8:853'] : ['https://1.1.1.1/dns-query','https://8.8.8.8/dns-query'];
    out.dns['default-nameserver'] = bootstrap;
    out.dns['proxy-server-nameserver'] = bootstrap;
  }
  if (out['allow-lan']) {
    out['bind-address'] = '0.0.0.0';
    out['lan-allowed-ips'] = [...PRIVATE_RANGES];
    if (s.lanPasswordRequired) {
      if (s.lanPassword.length < 8) throw new Error('LAN sharing requires a password of at least 8 characters');
      out.authentication = [`${s.lanUsername}:${s.lanPassword}`];
      out['skip-auth-prefixes'] = ['127.0.0.0/8'];
    }
  }
  const groupName = (out['proxy-groups'] || []).find(g => g.type === 'select')?.name || 'AZADNET';
  const rejectQuic = 'AND,((NETWORK,UDP),(DST-PORT,443)),REJECT';
  const rules = Array.isArray(out.rules) ? out.rules : [];
  if (s.routingMode === 'iran') {
    out.rules = [rejectQuic,'DOMAIN-SUFFIX,ir,DIRECT',...(opts.geoipAvailable ? ['GEOIP,IR,DIRECT,no-resolve'] : []),...rules.filter(r => r !== rejectQuic && r !== 'DOMAIN-SUFFIX,ir,DIRECT' && r !== 'GEOIP,IR,DIRECT,no-resolve')];
    if (opts.geoipAvailable) out['geodata-mode'] = true;
    if (s.iranRemoteRules) {
      out['rule-providers'] = {...out['rule-providers'], 'whitedns-iran': {type:'http',behavior:'classical',format:'text',url:IRAN_RULE_URL,path:'./ruleset/whitedns-iran.txt',interval:86400,proxy:groupName,'size-limit':10485760}};
      const finalMatch = out.rules.findIndex(r => r.startsWith('MATCH,'));
      out.rules.splice(finalMatch < 0 ? out.rules.length : finalMatch, 0, 'RULE-SET,whitedns-iran,DIRECT');
    }
  } else if (s.routingMode === 'global') {
    out.rules = [rejectQuic, ...rules.filter(r => r.startsWith('IP-CIDR,') && PRIVATE_RANGES.some(cidr => r === `IP-CIDR,${cidr},DIRECT,no-resolve`)), `MATCH,${groupName}`];
  } else if (!rules.length) out.rules = [rejectQuic, `MATCH,${groupName}`];
  return out;
}

module.exports = {ADVANCED_DEFAULTS, FRAGMENT_PRESETS, parseFragments, parseFrontingEndpoint, validateAdvanced, applyAdvanced};
