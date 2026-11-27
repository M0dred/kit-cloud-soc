'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const root=path.join(__dirname,'../docs');
const html=fs.readFileSync(path.join(root,'flow.html'),'utf8');
const css=fs.readFileSync(path.join(root,'flow.css'),'utf8');
const js=fs.readFileSync(path.join(root,'flow.js'),'utf8');
assert.match(fs.readFileSync(path.join(root,'index.html'),'utf8'),/href="flow\.html">3D flow demo \(synthetic\)/);
assert.match(html,/SYNTHETIC DEMO/);
assert.match(html,/connect-src 'none'/);
assert.match(html,/Not shown \/ unverified/);
assert.deepEqual([...html.matchAll(/\b(?:src|href)="([^"]+)"/g)].map(([,v])=>v),['flow.css','flow.js','#content','./','activity.html']);
const addresses=[...js.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)].map(([ip])=>ip);
assert.equal(new Set(addresses).size,3);
assert(addresses.every(ip=>/^(192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}$/.test(ip)));
assert.match(css,/prefers-reduced-motion\s*:\s*reduce/);
assert(!/\b(?:fetch|XMLHttpRequest|WebSocket|EventSource|sendBeacon|localStorage)\b/.test(js));

class Element {
  constructor(tag='div') { this.tag=tag;this.children=[];this.listeners={};this.attrs={};this.textContent='';this.hidden=true; }
  setAttribute(k,v) { this.attrs[k]=v; }
  appendChild(el) { this.children.push(el); }
  replaceChildren() { this.children=[]; }
  addEventListener(name,fn) { this.listeners[name]=fn; }
}
const ids=[...html.matchAll(/\bid="([^"]+)"/g)].map(([,id])=>id);
assert.equal(ids.length,new Set(ids).size);
const ui=Object.fromEntries(ids.map(id=>[id,new Element()]));
ui.angle.value='-18';
let tick=null, timerCount=0;
vm.runInNewContext(js,{document:{getElementById:id=>ui[id],createElement:tag=>new Element(tag),
  createElementNS:(ns,tag)=>{assert.equal(ns,'http://www.w3.org/2000/svg');return new Element(tag);}},
  setInterval:(fn,ms)=>{assert.equal(ms,2000);tick=fn;return ++timerCount;},
  clearInterval:id=>{assert(id>0);tick=null;}},{timeout:2000});
const edge=()=>ui.edges.children.find(e=>e.attrs.class==='active');
const click=id=>ui[id].listeners.click();
assert.equal(ui.replay.hidden,false);
assert.equal(tick,null,'Replay must be paused by default');
assert.equal(ui.previous.disabled,true);
assert.match(ui['step-label'].textContent,/Event 1 of 6.*UTC \(fictional\)/);
assert.equal(ui.nodes.children.length,12);
assert.equal(edge().attrs['marker-end'],'url(#flow-arrow)');
const start=edge().attrs.d;
for (const angle of ['-38','38','18']) {
  ui.angle.value=angle;ui.angle.listeners.input();
  assert.notEqual(edge().attrs.d,start);
  assert.equal(ui['angle-label'].textContent,`${angle}°`);
  const labels=ui.nodes.children.filter(n=>n.tag==='text');
  assert(labels.every(n=>Number(n.attrs.x)>80 && Number(n.attrs.x)<660 && Number(n.attrs.y)>35 && Number(n.attrs.y)<330));
}
click('flat');
assert.equal(ui.angle.disabled,true);
assert.equal(ui.flat.attrs['aria-pressed'],'true');
const flat=edge().attrs.d;ui.angle.value='0';ui.angle.listeners.input();assert.equal(edge().attrs.d,flat);
click('flat');assert.equal(ui.angle.disabled,false);
click('next');assert.equal(ui.observer.textContent,'Clear NDR Demo');
assert.equal(ui.edges.children.filter(e=>e.attrs.class==='earlier').length,1);
click('previous');assert.match(ui['step-label'].textContent,/Event 1 of 6/);
click('play');assert.equal(ui.play.textContent,'Pause');assert.equal(ui.edges.children.at(-1).attrs.class,'trace');
for(let i=0;i<5;i++) tick();
assert.equal(tick,null);assert.equal(ui.play.textContent,'Replay');assert.equal(ui.next.disabled,true);
click('play');assert.match(ui['step-label'].textContent,/Event 1 of 6/);click('play');assert.equal(tick,null);
ui.step.value='4';ui.step.listeners.input();assert.match(ui['step-label'].textContent,/Event 4 of 6/);
ui['event-list'].children[2].children[0].listeners.click();assert.match(ui.behavior.textContent,/HTTP/);
assert.match(ui.result.textContent,/exploitation not established/);
assert.match(ui['scene-description'].textContent,/Target and compromise not established/);
console.log('Synthetic flow: perspective, 2D, keyboard controls, playback and offline privacy checks OK');
