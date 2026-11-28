'use strict';
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const docs = path.resolve(__dirname, '../docs');
const treeScript = fs.readFileSync(path.join(docs, 'tree.js'), 'utf8');
const appScript = fs.readFileSync(path.join(docs, 'app.js'), 'utf8');
const page = fs.readFileSync(path.join(docs, 'index.html'), 'utf8');
const current = '2026-11-26 12:01 UTC', previous = '2026-11-26 06:06 UTC';
const ip = '192.0.2.11';
const snapshot = {generated: current, wazuh:{top_src:[[ip,7]], total_7d:10,
  pipeline_24h_coverage:{outside_top_alerts:null}, by_day:[], source_context:{}},
  misp:{total:3, top_source_membership:{[ip]:true}}, blocklist_n:0};
const baseline = {schema_version:1, current_utc:current, previous_utc:previous,
  metrics:{alerts_7d:[4,10],outside_top_500_alerts:[6,null],misp_ip_attributes:[5,3],watchlist:[0,0]},
  sources:{entered:1,left:1,retained:0,changed_alert_counts:0}};
class Element {
  constructor(tag='div') { this.tag = tag; this.children = []; this.listeners = {}; this.style = {}; this.value = ''; this._text = ''; }
  get textContent() { return this._text+this.children.map(c=>c.textContent).join(''); }
  set textContent(text) { this._text = String(text); this.children = []; }
  set innerHTML(_) { throw Error('Unsafe DOM write'); }
  appendChild(child) { this.children.push(child); }
  replaceChildren() { this.textContent = ''; }
  setAttribute(k,v) { this[k] = v; }
  addEventListener(k,v) { this.listeners[k] = v; }
}
async function load(diff, data=snapshot) {
  const ids=Object.fromEntries([...page.matchAll(/\bid="([^\"]+)"/g)].map(([,id])=>[id,new Element()]));
  const state=new Element('p'), tree=new Element('div'), calls=[];
  ids.changes.querySelector = selector => ({'[role=status]':state, '.diff-tree':tree})[selector];
  const document={createElement: tag=>new Element(tag), getElementById: id=>ids[id]};
  const signal={schema_version:1,state:'degraded',last_attempt_utc:'2026-11-26 18:01 UTC'};
  const FixedDate=class extends Date { static now() { return Date.parse('2026-11-26T20:00Z'); } };
  const sandbox=vm.createContext({document,console,Date:FixedDate,fetch:async url=>{
    calls.push(url);
    assert(['data.json','status.json','snapshot-diff.json'].includes(url),'Unexpected external request');
    return {ok:url !== 'snapshot-diff.json' || diff !== undefined,
      json:async()=>({'data.json':data,'status.json':signal,'snapshot-diff.json':diff})[url]};
  }});
  vm.runInContext(fs.readFileSync(path.join(docs,'public-view.js'),'utf8'),sandbox,{timeout:2000});
  vm.runInContext(fs.readFileSync(path.join(docs,'published-refresh.js'),'utf8'),sandbox,{timeout:2000});
  vm.runInContext(treeScript,sandbox,{timeout:2000});
  await vm.runInContext(appScript,sandbox,{timeout:2000});
  return {state,tree,ids,calls};
}
(async()=>{
  assert(page.indexOf('src="tree.js"')<page.indexOf('src="app.js"'));
  const {tree,state,calls,ids}=await load(baseline);
  assert.deepEqual(tree.children.map(n=>n.tag),['details','details','details'],
    `${state.textContent} | ${ids.gen.textContent} | fetches: ${calls.join(', ')}`);
  assert.match(state.textContent,/06:06 UTC.*12:01 UTC/);
  assert.match(tree.textContent,/4 → 10 \(\+6\)/);
  assert.match(tree.textContent,/5 → 3 \(−2\)/);
  assert.match(tree.textContent,/N\/A \(change unknown\)/);
  assert.match(tree.textContent,/leaving it does not mean/);
  assert.equal(ids['status-pill'].textContent,'PIPELINE DEGRADED');
  ids.src.children[1].children[0].children[0].children[0].listeners.click();
  const refs=ids['ioc-detail'].children.find(el=>el.className==='refs');
  const destinations=new Map(refs.children.map(link=>[link.textContent,link.href]));
  assert.equal(destinations.size,6);
  assert.equal(destinations.get('AlienVault OTX'),`https://otx.alienvault.com/indicator/ip/${ip}`);
  for (const link of refs.children) {
    assert.equal(link.target,'_blank'); assert.equal(link.rel,'noopener noreferrer');
    assert.equal(link.referrerPolicy,'no-referrer'); assert.match(link.href,/^https:\/\//);
    assert(link.href.endsWith('/'+ip));
  }
  assert.deepEqual(calls,['data.json','status.json','snapshot-diff.json']);
  for (const diff of [undefined,{...baseline,current_utc:previous},{...baseline,previous_utc:current},
    {...baseline,metrics:{...baseline.metrics,alerts_7d:[4,9]}},
    {...baseline,sources:{...baseline.sources,entered:2}}]) {
    const other=await load(diff);
    assert.match(other.state.textContent,/could be verified/);
    assert.equal(other.tree.children.length,0);
    assert.equal(other.ids.kpis.children.length,2);
  }
  const empty=await load({...baseline,previous_utc:null,metrics:null,sources:null});
  assert.match(empty.state.textContent,/No previous comparable batch/);
  const correction=await load(baseline,{...snapshot,public_revision:{kind:'projection_correction'}});
  assert.match(correction.state.textContent,/display-only correction/);
  assert(!correction.calls.includes('snapshot-diff.json'));
  console.log('Snapshot tree, batch alignment and click-only external lookup tests OK');
})().catch(e=>{console.error(e);process.exitCode=1;});
