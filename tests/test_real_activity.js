'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const docs = path.resolve(__dirname, '../docs');
const html = fs.readFileSync(path.join(docs,'activity.html'),'utf8');
const script = ['public-view.js','published-refresh.js','activity.js'].map(f=>fs.readFileSync(path.join(docs,f),'utf8')).join('\n');
assert.match(html,/REAL AGGREGATES · NOT LIVE/);
assert.match(html,/connect-src 'self'/);
assert.match(html,/No hourly or geographical inference/);
assert.match(fs.readFileSync(path.join(docs,'index.html'),'utf8'),/href="activity\.html">UTC activity/);
assert(!/source_context|top_src|enrich_meta|by_agent|destination_ip/.test(script));
const nodes = [...html.matchAll(/\bid="([^"]+)"/g)].map(([,id])=>id);
assert.equal(nodes.length,new Set(nodes).size);
class Element {
  constructor(tag) {this.tag=tag;this.children=[];this.handlers={};this.attrs={};this.textContent='';this.hidden=true;}
  appendChild(child) {this.children.push(child);}
  setAttribute(k,v) {this.attrs[k]=v;}
  replaceChildren() {this.children=[];}
  addEventListener(event,fn) {this.handlers[event]=fn;}
}
const fixture={generated:'2026-11-26 12:01 UTC',wazuh:{total_7d:28,
  by_day:[0,1,2,3,4,5,6,7].map((n,i)=>[`2026-11-${19+i}`,n])}};
const report={schema_version:1,state:'degraded',last_attempt_utc:'2026-11-26 22:01 UTC'};
async function run(data, status=report, now='2026-11-27T05:03:00Z') {
  const rendered=Object.fromEntries(nodes.map(id=>[id,new Element('div')]));
  rendered.azimuth.value='-23';rendered.elevation.value='24';
  const fetched=[];
  const Clock=class extends Date {static now(){return Date.parse(now);}};
  const doc={getElementById:id=>rendered[id],createElement:tag=>new Element(tag),
    createElementNS:(ns,tag)=>{assert.equal(ns,'http://www.w3.org/2000/svg');return new Element(tag);}};
  await vm.runInNewContext(script,{Date:Clock,document:doc,fetch:async url=>{
    assert(['data.json','status.json'].includes(url));fetched.push(url);
    const body=url==='data.json'?data:status;
    return {ok:body!==null,json:async()=>body};
  }},{timeout:2000});
  assert.deepEqual(fetched,['data.json','status.json']);
  return rendered;
}
(async()=>{
  const r=await run(fixture);
  assert.match(r['batch-status'].textContent,/26 12:01 UTC/);
  assert.match(r.heartbeat.textContent,/22:01 UTC · degraded.*last published/);
  assert.match(r.coverage.textContent,/28 alerts.*reconcile.*may be partial/);
  assert.equal(r['heat-grid'].children.length,8);
  assert.equal(r['heat-grid'].children[0].className,'heat-0');
  assert.equal(r['heat-grid'].children[7].className,'heat-5');
  assert.equal(r.columns.hidden,true);
  assert.equal(r['volume-bars'].children.length,0);
  r['show-columns'].handlers.click();
  assert.equal(r.columns.hidden,false);
  assert.equal(r['show-columns'].attrs['aria-expanded'],'true');
  assert.equal(r['volume-bars'].children.filter(n=>n.tag==='polygon').length,22); // seven columns and one flat zero
  const saved=()=>r['volume-bars'].children[0].attrs.points;
  const first=saved();r.azimuth.value='35';r.azimuth.handlers.input();assert.notEqual(saved(),first);
  const second=saved();r.elevation.value='35';r.elevation.handlers.input();assert.notEqual(saved(),second);
  for (const angle of ['-35','35']) {
    r.azimuth.value=angle;r.azimuth.handlers.input();
    assert(r['volume-bars'].children.filter(n=>n.tag==='text').every(n=>+n.attrs.y<328 && +n.attrs.y>0));
  }
  r['show-columns'].handlers.click();assert.equal(r.columns.hidden,true);
  const missing=structuredClone(fixture);missing.wazuh.by_day.splice(1,1);
  const m=await run(missing,null);
  assert.match(m.coverage.textContent,/missing is not zero/);
  assert.match(m.heartbeat.textContent,/heartbeat unverified/);
  assert.equal(m['heat-grid'].children[1].className,'heat-unknown');
  assert.equal(m['heat-grid'].children[1].children[1].textContent,'N/A');
  m['show-columns'].handlers.click();
  assert.equal(m['volume-bars'].children.filter(n=>n.tag==='polygon').length,19);
  const empty=structuredClone(fixture);empty.wazuh.by_day=[];
  assert.equal((await run(empty))['show-columns'].hidden,true);
  const duplicate=structuredClone(fixture);duplicate.wazuh.by_day[1]=duplicate.wazuh.by_day[0];
  assert.match((await run(duplicate))['batch-status'].textContent,/No verified/);
  assert.match((await run(null))['batch-status'].textContent,/No verified/);
  assert.match((await run(fixture,report,'2026-11-28T03:00:00Z'))['batch-status'].textContent,/stale/);
  const published=JSON.parse(fs.readFileSync(path.join(docs,'data.json'),'utf8'));
  const actual=await run(published,null,new Date(Date.parse(published.generated.replace(' UTC','Z').replace(' ','T'))+3600000).toISOString());
  assert.match(actual['batch-status'].textContent,/Snapshot /);
  console.log('Real activity: aggregate-only daily heatmap, UTC, optional 3D, missing and degraded checks OK');
})().catch(error=>{console.error(error);process.exitCode=1;});
