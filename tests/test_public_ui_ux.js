'use strict';
const assert=require('node:assert/strict');
const {markup,brief,stamp}=require('./brief_dom');
const ip='192.0.2.11',generated='2026-11-26 22:01 UTC';
const data={generated,wazuh:{total_7d:12,top_src:[[ip,7]],by_day:[['2026-11-26',null]],
  source_context:{[ip]:{sample_behavior:'SSH authentication alert'}}},misp:{top_source_membership:{[ip]:true}}};
const report={schema_version:1,state:'ok',last_attempt_utc:generated};
(async()=>{
  assert.match(markup,/href="#main-content"/);assert.match(markup,/id="main-content"[^>]*tabindex="-1"/);
  const {ui,document}=await brief(data,report,{mobile:true,now:stamp(generated)+3600000});
  const body=ui.src.children[1],first=body.children[0].children[0].children[0],detail=ui['ioc-detail'];
  first.focus();first.listeners.click();
  assert.equal(body.children[1].className,'detail-row');assert.equal(body.children[1].children[0].children[0],detail);
  assert.equal(detail.hidden,false);assert.equal(document.activeElement,detail);assert.equal(first.attrs['aria-expanded'],'true');
  assert.match(detail.textContent,/SSH-related alert \(outcome unverified\)/);
  detail.children[0].children[1].listeners.click();assert.equal(document.activeElement,first);assert.equal(detail.hidden,true);
  first.listeners.click();ui['source-filter'].value=ip.replace(/\.(?=[^.]+$)/,'[.]');ui['source-filter'].listeners.input();
  assert.match(ui['source-scope'].textContent,/1 of 1/);assert.equal(detail.hidden,true);
  ui['source-filter'].value='nothere';ui['source-filter'].listeners.input();assert.match(ui['source-scope'].textContent,/No sources match/);
  assert.match(ui['day-values'].textContent,/N\/A/);assert(!ui.days.children[0].children.some(el=>el.tag==='svg'));
  const late=await brief(data,report,{now:Date.parse('2026-11-27T13:01Z')});
  assert.equal(late.ui['status-pill'].textContent,'HEARTBEAT OVERDUE');assert.match(late.ui.agents.textContent,/Last attempt.*ok.*2026-11-27 12:00 UTC slot unconfirmed/);
  const grace=await brief(data,report,{now:Date.parse('2026-11-27T06:29Z')});assert.equal(grace.ui['status-pill'].textContent,'LAST RUN OK');
  const missing=await brief(data,null,{now:stamp(generated)+3600000});assert.equal(missing.ui['status-pill'].textContent,'STATUS UNKNOWN');
  const empty=await brief({...data,wazuh:{...data.wazuh,top_src:[]}},report,{now:stamp(generated)+3600000});
  assert.match(empty.ui['source-scope'].textContent,/not zero alerts/);
  console.log('Evidence brief UX: mobile inline disclosure, filter, missing values and UTC schedule');
})().catch(e=>{console.error(e);process.exitCode=1;});
