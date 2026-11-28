'use strict';
const assert=require('node:assert/strict');const vm=require('node:vm');
const {read,brief}=require('./brief_dom');
const first='2026-11-26 22:01 UTC', second='2026-11-27 06:06 UTC';
const good=t=>({schema_version:1,state:'ok',last_attempt_utc:t});
const ip='192.0.2.11',d={generated:first,wazuh:{total_7d:10,top_src:[[ip,7]],by_day:[],source_context:{}},misp:{top_source_membership:{[ip]:true}}};
(async()=>{
  // Integrate the old-looking page with the real refresh and inspector code.
  assert.match(read('classic.html'),/data-view="classic"/);assert.match(read('index.html'),/href="classic.html"/);
  const {ui,feed,calls}=await brief(d,good(first),{mobile:true,classic:true,now:Date.parse('2026-11-27T06:19Z')});
  assert.equal(ui.kpis.children.length,4);
  assert.equal(ui['status-pill'].textContent,'LAST RUN OK');
  const row=ui.src.children[1].children[0],button=row.children[0].children[0];
  button.listeners.click();
  feed.report={...good(second),state:'degraded'};
  await ui['refresh-now'].listeners.click();
  assert.equal(ui['status-pill'].textContent,'PIPELINE DEGRADED');
  assert.equal(ui.src.children[1].children[0],row,'heartbeat-only must not replace source rows');
  assert.match(ui.gen.textContent,/22:01 UTC/);assert.equal(ui['ioc-detail'].hidden,false);
  feed.data={...d,generated:second,wazuh:{...d.wazuh,total_7d:12,top_src:[[ip,9]]}};
  feed.report=good('2026-11-27 06:07 UTC');await ui['refresh-now'].listeners.click();
  assert.match(ui.gen.textContent,/06:06 UTC/);assert.match(ui['ioc-detail'].textContent,/9 Wazuh alerts/);
  assert.equal(ui['ioc-detail'].hidden,false);
  feed.data=d;feed.report=good(first);await ui['refresh-now'].listeners.click();
  assert.match(ui.gen.textContent,/06:06 UTC/);assert.match(ui['refresh-status'].textContent,/refresh incomplete/);
  assert.equal(ui['status-pill'].textContent,'REFRESH UNVERIFIED');
  feed.dataAvailable=false;await ui['refresh-now'].listeners.click();assert.match(ui['ioc-detail'].textContent,/9 Wazuh alerts/);
  assert(calls.every(x=>['data.json','status.json'].includes(x)));
  // Run the scheduling code with a foreground/background document, no real timers.
  let scheduled,onVisibility,collect=0,allow;
  const history=[],elements={};
  const document={hidden:false,getElementById:id=>elements[id]??=( {addEventListener(){},setAttribute(){}} ),addEventListener:(name,fn)=>{assert.equal(name,'visibilitychange');onVisibility=fn;}};
  const Clock=class extends Date{static now(){return Date.parse('2026-11-27T07:00Z');}};
  const ctx=vm.createContext({window:{setInterval(fn,ms){assert.equal(ms,60000);scheduled=fn;}},document,Date:Clock,
    fetch:async url=>{collect++;if(allow)await allow;return{ok:true,json:async()=>url==='data.json'?d:good(first)};},history});
  vm.runInContext(read('public-view.js'),ctx);vm.runInContext(read('published-refresh.js'),ctx);
  const r=vm.runInContext('publishedRefresh({accept:()=>true,paint:x=>history.push(x)})',ctx);
  await r.start();assert.equal(collect,2);
  document.hidden=true;scheduled();assert.equal(collect,2);
  let release;allow=new Promise(r=>{release=r;});document.hidden=false;onVisibility();
  assert.equal(collect,4);const active=r.poll();assert.equal(r.poll(),active);release();await active;
  assert.equal(collect,4);assert.equal(history[1].changed,false);
  console.log('Published refresh: classic layout, unchanged view, batch update, regression guard, and foreground timer');
})().catch(e=>{console.error(e);process.exitCode=1;});
