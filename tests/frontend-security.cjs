// Offline regression tests: evaluate the actual dashboard with minimal DOM/API doubles.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const html = fs.readFileSync(__dirname + '/../index.html', 'utf8');
const source = html.match(/<script type="module">([\s\S]*?)<\/script>/)[1]
  .replace(/import\s*\{\s*createClient\s*\}\s*from\s*"[^"]+";/, '')
  .replace(/\binit\(\);\s*$/, '');
const elements = new Map();
function element(id) {
  if (!elements.has(id)) {
    const classes = new Set();
    elements.set(id, {
      textContent: '', innerHTML: '', value: '', handlers: {}, attrs: {},
      classList: {add(v){classes.add(v)}, remove(v){classes.delete(v)}, toggle(){}, contains(v){return classes.has(v)}},
      addEventListener(name,fn){this.handlers[name]=fn}, querySelectorAll(){return []},
      replaceChildren(){this.innerHTML='';this.textContent=''}, removeAttribute(k){delete this.attrs[k]}
    });
  }
  return elements.get(id);
}
const requests = [], unrolled = [];
let factors = [], aal = 'aal2', pairingResolve;
const supabase = {
  auth: {onAuthStateChange(){}, signOut: async () => ({error: null}), mfa: {
    getAuthenticatorAssuranceLevel: async()=>({data:{currentLevel:aal}}),
    listFactors: async()=>({data:{totp:factors}}),
    unenroll: async ({factorId})=>{unrolled.push(factorId);factors=factors.filter(f=>f.id!==factorId);return {error:null}}
  }},
  rpc: ()=>new Promise(resolve=>pairingResolve=resolve),
  from(table) {
    let network;
    const chain = {
      select(){return chain}, eq(k,v){network=v; return chain},
      order(){return chain}, limit(){return chain},
      then(resolve){ requests.push({table, network, resolve}); }
    };
    return chain;
  }
};
const context = vm.createContext({
  createClient: () => supabase,
  Option: function(text,value){this.text=text;this.value=value},
  document: {getElementById: element, querySelectorAll: s=>s==='.modal-backdrop'?[element('deviceModal'),element('mfaSetupModal')]:[]},
  window: {addEventListener(){}, removeEventListener(){}},
  navigator: {}, console, setTimeout, clearTimeout, setInterval, clearInterval,
  localStorage: {getItem(){},setItem(){}}
});
vm.runInContext(source, context);
const run = s=>vm.runInContext(s,context);
(async () => {
  run('renderEverything = () => {}; currentUser={id:"user"}; selectedNetwork = {id:"A", name:"A"}');
  const old = run('loadNetworkData()');
  await Promise.resolve();
  run('selectedNetwork = {id:"B", name:"B"}');
  const latest = run('loadNetworkData()');
  await Promise.resolve();
  for (const r of requests.filter(r=>r.network==='B')) r.resolve({data:[{id:'B-result'}]});
  await latest;
  for (const r of requests.filter(r=>r.network==='A')) r.resolve({data:[{id:'A-result'}]});
  await old;
  assert.equal(run('devices[0].id'),'B-result');
  console.log('PASS network response ordering');

  requests.length=0;
  const late = run('loadNetworkData()');
  await Promise.resolve();
  element('deviceDetailContent').innerHTML = 'private device';
  element('mfaSecret').textContent = 'TOTP seed';
  element('mfaQr').attrs.src='secret QR';
  await run('logoutLocal()');
  for (const r of requests) r.resolve({data:[{id:'late-private'}]});
  await late;
  assert.equal(run('devices.length + agents.length + networks.length + events.length + alerts.length + learnedFingerprints.length'),0);
  assert.equal(run('selectedNetwork'),null);
  assert.equal(element('deviceDetailContent').innerHTML,'');
  assert.equal(element('mfaSecret').textContent,'');
  assert.equal(element('mfaQr').attrs.src,undefined);
  assert.ok(element('deviceModal').classList.contains('hidden'));
  console.log('PASS logout state/DOM and late-response isolation');

  run('currentUser={id:"user"}; selectedNetwork={id:"A"}');
  const pairing=run('openPairing()');
  run('selectedNetwork={id:"B"}');
  pairingResolve({data:{code:'old-network-code',expires_at:new Date().toISOString()}});
  await pairing;
  assert.equal(element('pairingCode').textContent,'');
  console.log('PASS stale pairing response isolation');

  run('askConfirm=async()=>true');
  const remove=element('mfaFactors').handlers.click;
  const button={dataset:{factorId:'one'},disabled:false};
  const event={target:{closest:()=>button}};
  factors=[{id:'one',status:'verified'}];
  await remove(event);
  assert.equal(unrolled.length,0);
  factors.push({id:'two',status:'verified'});
  aal='aal1';
  await remove(event);
  assert.equal(unrolled.length,0);
  aal='aal2';
  await remove(event);
  assert.deepEqual(unrolled,['one']);
  assert.equal(factors.length,1);
  console.log('PASS MFA removal: last factor blocked, AAL1 blocked, AAL2 allowed');

  const mobile=html.slice(html.indexOf('max-width: 760px'),html.indexOf('</style>'));
  assert.match(mobile,/\.sidebar-bottom\s*\{\s*display:\s*block/);
  console.log('PASS mobile sign-out visibility');
})().catch(error=>{console.error(error);process.exitCode=1});
