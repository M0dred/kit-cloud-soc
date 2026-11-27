'use strict';
const assert=require('node:assert/strict');
const {read,markup,snapshot,stamp,brief}=require('./brief_dom');
const healthy={schema_version:1,state:'ok',last_attempt_utc:snapshot.generated};
const base=stamp(snapshot.generated);
(async()=>{
  const ids=[...markup.matchAll(/\bid="([^"]+)"/g)].map(([,v])=>v);assert.equal(ids.length,new Set(ids).size);
  assert.match(markup,/style-src 'self'/);assert(!markup.includes('unsafe-inline'));assert(!read('app.js').includes('innerHTML'));
  const {ui,calls}=await brief(snapshot,healthy,{now:base+3600000});
  assert.equal(ui['status-pill'].textContent,'LAST RUN OK');assert.match(ui.gen.textContent,/Snapshot/);
  assert.equal(ui.kpis.children.length,2);assert.match(ui['catalog-metrics'].textContent,/VT deduplication entries/);
  assert.match(ui['snapshot-note'].textContent,/not live/);assert(ui['day-values'].children.length>0);
  assert.deepEqual(calls,['data.json','status.json']);
  const d=await brief(snapshot,{...healthy,state:'degraded'},{now:base+3600000});assert.equal(d.ui['status-pill'].textContent,'PIPELINE DEGRADED');
  const s=await brief(snapshot,healthy,{now:base+48*3600000});assert.equal(s.ui['status-pill'].textContent,'STALE SNAPSHOT');assert.match(s.ui.agents.textContent,/overdue/);
  assert(!JSON.stringify(snapshot).includes('samples_by_source'));
  console.log('Evidence brief smoke: strict CSP, scope, stale and degraded are distinct');
})().catch(e=>{console.error(e);process.exitCode=1;});
