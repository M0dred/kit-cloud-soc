'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const dir=path.join(__dirname,'../docs');
const html=fs.readFileSync(path.join(dir,'flow.html'),'utf8');
const js=fs.readFileSync(path.join(dir,'flow.js'),'utf8');
assert.match(fs.readFileSync(path.join(dir,'index.html'),'utf8'),/href="flow\.html">Observed source countries/);
assert.match(html,/REAL BATCH · AGGREGATE ONLY/);
assert.match(html,/connect-src 'self'/);
assert.match(html,/not an attacker’s nationality/);
assert.deepEqual([...html.matchAll(/\b(?:src|href)="([^"]+)"/g)].map(([,v])=>v),['flow.css','country-flow.css','flow.js','#content','./','activity.html']);

class Element {
  constructor(tag){this.tag=tag;this.children=[];this.listeners={};this.attrs={};this.hidden=true;this.value='';this.textContent='';}
  appendChild(el){this.children.push(el);}
  replaceChildren(){this.children=[];}
  setAttribute(k,v){this.attrs[k]=v;}
  addEventListener(k,fn){this.listeners[k]=fn;}
}
const text = el => [el.textContent,...el.children.map(text)].join(' ');
const ids=[...html.matchAll(/\bid="([^"]+)"/g)].map(([,id])=>id);
assert.equal(ids.length,new Set(ids).size);
const ips=['192.0.2.1','192.0.2.2','192.0.2.3','192.0.2.4','192.0.2.5'];
const snapshot={generated:'2026-11-26 12:01 UTC',wazuh:{total_7d:42,
  top_src:[[ips[0],20],[ips[1],4],[ips[2],6],[ips[3],0],[ips[4],3]],
  source_context:{[ips[0]]:{sample_behavior:'SSH authentication alert'},[ips[1]]:{sample_behavior:'PRIVATE_RAW_SAMPLE'}}},
  misp:{top_source_membership:{[ips[0]]:true,[ips[1]]:false}},
  enrich_meta:{[ips[0]]:{country:'CN',sources:{otx:{state:'fresh'},gn:{state:'fresh',last_attempt:'rate_limited'}}},
    [ips[1]]:{country:'US'},[ips[2]]:{country:'US'},[ips[3]]:{country:'US'},[ips[4]]:{country:'XX'}}};
const signal={schema_version:1,state:'degraded',last_attempt_utc:'2026-11-26 22:01 UTC'};
async function run(data, report=signal, now='2026-11-27T05:11:00Z') {
  const ui=Object.fromEntries(ids.map(id=>[id,new Element('div')]));
  ui['chart-flat'].hidden=false;
  ui['country-angle'].value='-15';ui['country-tilt'].value='22';
  const fetched=[];
  const Clock=class extends Date {static now(){return Date.parse(now);}};
  await vm.runInNewContext(js,{Date:Clock,document:{getElementById:id=>ui[id],createElement:tag=>new Element(tag),
    createElementNS:(ns,tag)=>{assert.equal(ns,'http://www.w3.org/2000/svg');return new Element(tag);}},
    fetch:async name=>{
      assert(['data.json','status.json'].includes(name));fetched.push(name);
      const v=name==='data.json'?data:report;return{ok:v!==null,json:async()=>v};
    }},{timeout:2000});
  assert.deepEqual(fetched,['data.json','status.json']);
  return ui;
}
(async()=>{
  const ui=await run(snapshot);
  assert.equal(ui.workspace.hidden,false);
  assert.equal(ui['selected-alerts'].textContent,'33');
  assert.equal(ui['total-alerts'].textContent,'42');
  assert.equal(ui['labelled-rows'].textContent,'4 / 5');
  assert.match(ui['country-heartbeat'].textContent,/22:01 UTC · degraded.*last published/);
  const groups=()=>ui['country-rows'].children.map(text);
  assert.match(groups()[0],/China.*20.*60.6%.*1/);
  assert.match(groups()[2],/Unknown country.*3/);
  assert.match(text(ui['country-detail']),/Present: 1 · Absent: 0 · Unknown: 0/);
  assert.match(text(ui['country-detail']),/SSH authentication alert: 1/);
  assert.match(text(ui['country-detail']),/GreyNoise\s+0\s+0\s+1\s+0/);
  assert.equal(ui['chart-depth'].hidden,true);
  const first=ui['country-bars'].children[0].children[1];assert.equal(first.value,20);assert.equal(first.max,20);
  ui.measure.value='rows';ui.measure.listeners.change();assert.match(groups()[0],/United States/);
  ui['country-rows'].children[0].children[0].children[0].listeners.click();
  assert.match(text(ui['country-detail']),/Present: 0 · Absent: 1 · Unknown: 2/);
  assert.match(text(ui['country-detail']),/No sample label available: 3/);
  const combined=Object.values(ui).map(text).join(' ');
  assert(ips.every(ip=>!combined.includes(ip)));
  assert(!combined.includes('PRIVATE_RAW_SAMPLE'));
  ui['toggle-depth'].listeners.click();assert.equal(ui['chart-depth'].hidden,false);
  const positions=()=>ui['country-shapes'].children[0].attrs.points;
  const start=positions();ui['country-angle'].value='30';ui['country-angle'].listeners.input();assert.notEqual(positions(),start);
  const rotated=positions();ui['country-tilt'].value='32';ui['country-tilt'].listeners.input();assert.notEqual(positions(),rotated);
  ui['toggle-depth'].listeners.click();assert.equal(ui['chart-flat'].hidden,false);
  const blank=await run({...snapshot,wazuh:{total_7d:42,top_src:[]}},null);
  assert.match(blank['country-heartbeat'].textContent,/heartbeat unavailable/);
  assert.match(text(blank['country-detail']),/does not mean no alerts/);
  const malformed=structuredClone(snapshot);malformed.wazuh.top_src.push([ips[0],1]);
  assert.match((await run(malformed))['country-batch'].textContent,/No verified/);
  assert.match((await run(snapshot,signal,'2026-11-28T02:00Z'))['country-batch'].textContent,/over 24 hours old/);
  const real=JSON.parse(fs.readFileSync(path.join(dir,'data.json'),'utf8'));
  const now=new Date(Date.parse(real.generated.replace(' UTC','Z').replace(' ','T'))+3600000).toISOString();
  const actual=await run(real,null,now);
  assert.equal(actual['selected-alerts'].textContent,real.wazuh.top_src.reduce((a,[,n])=>a+n,0).toLocaleString());
  assert(real.wazuh.top_src.every(([ip])=>!Object.values(actual).map(text).join(' ').includes(ip)));
  console.log('Country flow: real snapshot aggregation, masked output, uncertainty, detail and optional 3D checks OK');
})().catch(error=>{console.error(error);process.exitCode=1;});
