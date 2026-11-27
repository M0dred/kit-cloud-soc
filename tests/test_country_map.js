'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const docs=path.resolve(__dirname,'../docs');
const world=JSON.parse(fs.readFileSync(path.join(docs,'world-map.json'),'utf8'));
const data=JSON.parse(fs.readFileSync(path.join(docs,'data.json'),'utf8'));
const html=fs.readFileSync(path.join(docs,'flow.html'),'utf8');
const ids=[...html.matchAll(/\bid="([^"]+)"/g)].map(([,id])=>id);
assert.equal(ids.length,new Set(ids).size);
assert.match(html,/id="pulse-map".*?aria-labelledby=/);
assert.match(html,/Not a destination/);
assert.match(html,/not routes or live events/);
assert.match(html,/connect-src 'self'/);
assert.equal(world.source,'Natural Earth 5.1.2 / admin 0 countries 1:110m');
class Element {
  constructor(tag){this.tag=tag;this.children=[];this.attrs={};this.listeners={};this.hidden=true;this.value='';this.textContent='';}
  appendChild(el){this.children.push(el);}
  replaceChildren(){this.children=[];}
  setAttribute(k,v){this.attrs[k]=v;}
  addEventListener(k,fn){this.listeners[k]=fn;}
}
const script=fs.readFileSync(path.join(docs,'country-map.js'),'utf8');
const app=fs.readFileSync(path.join(docs,'flow.js'),'utf8');
async function fixture({shape=world,reduced=false,snapshot=data}={}) {
  const ui=Object.fromEntries(ids.map(id=>[id,new Element('div')]));
  ui['chart-flat'].hidden=false;
  const touched=[];let tick=null;
  const Clock=class extends Date {static now(){return Date.parse(data.generated.replace(' UTC','Z').replace(' ','T'))+3600000;}};
  const sandbox={document:{getElementById:id=>ui[id],createElement:tag=>new Element(tag),
    createElementNS:(ns,tag)=>{assert.equal(ns,'http://www.w3.org/2000/svg');return new Element(tag);}},
    Date:Clock,matchMedia:()=>({matches:reduced}),setInterval:(fn,ms)=>{assert.equal(ms,2000);tick=fn;return 1;},clearInterval:()=>{tick=null;},
    fetch:async p=>{touched.push(p);const values={'data.json':snapshot,'status.json':null,'world-map.json':shape};assert(Object.hasOwn(values,p));
      return {ok:values[p]!==null,json:async()=>values[p]};}};
  vm.createContext(sandbox);vm.runInContext(script,sandbox,{timeout:2000});await vm.runInContext(app,sandbox,{timeout:2000});
  // The outline is independent of the snapshot read, so wait one task before checking it.
  await new Promise(resolve=>setImmediate(resolve));
  assert.deepEqual(touched.sort(),['data.json','status.json','world-map.json']);
  return {ui,tick:()=>tick};
}
function getGroups(data) {
  const out=new Map();
  for (const [ip,count] of data.wazuh.top_src) {
    const label=data.enrich_meta?.[ip]?.country;
    const code=['TW','HK'].includes(label)?'CN':label;
    if (!code || !Object.hasOwn(world.anchors,code)) continue;
    out.set(code,(out.get(code)||0)+count);
  }
  return [...out].sort((a,b)=>b[1]-a[1]||a[0].localeCompare(b[0]));
}
function includesIp(node){return [node.textContent,...node.children.map(includesIp)].join(' ');}
(async()=>{
  const {ui,tick}=await fixture();
  assert.equal(ui['map-figure'].hidden,false);
  assert.match(ui['map-status'].textContent,/Mapped \d+ of \d+ published/);
  const ranked=getGroups(data);
  const paths=()=>ui['map-arcs'].children.filter(e=>e.tag==='path');
  const dots=()=>ui['map-arcs'].children.filter(e=>e.attrs.class==='map-pulses');
  assert.equal(tick(),null);
  assert.equal(ui['map-land'].children.length,world.land.length);
  assert.equal(paths().length,0);
  assert.equal(ui['country-map'].attrs.viewBox,'0 0 705 354');
  assert.equal(ui['map-destination'].attrs.class,'map-hidden');
  assert(ui['map-legend-values'].children.some(c=>includesIp(c).includes('Not in mapped subset')));
  const raw=Object.values(ui).map(includesIp).join(' ');
  assert(data.wazuh.top_src.every(([ip])=>!raw.includes(ip)));
  if(ranked.length){
    const [code,min]=ranked[0];
    assert.equal(ui['map-focus'].value,code);
    assert.equal(ui['map-selection-count'].textContent,`${min.toLocaleString()} bucket alerts`);
    ui['map-play'].listeners.click();assert.equal(ui['map-play'].textContent,'Pause pulse');
    assert.equal(paths().length,ranked.length);
    assert(paths().every(path=>path.attrs.d.endsWith('725 193')));
    assert.equal(ui['country-map'].attrs.viewBox,'0 0 896 354');
    assert.equal(dots().length,1);
    assert.equal(dots()[0].children[0].attrs.repeatCount,'indefinite');
    if(ranked.length>1){tick()();assert.equal(ui['map-focus'].value,ranked[1][0]);}
    while(tick())tick()();
    assert.equal(dots().length,0);
    const pick=ranked.at(-1)[0];ui['map-focus'].value=pick;ui['map-focus'].listeners.change();
    assert.equal(ui['map-focus'].value,pick);
    assert(ui['country-rows'].children.some(tr=>tr.children[0].children[0].attrs['aria-pressed']==='true'));
    ui['map-links-toggle'].listeners.click();assert.equal(paths().length,0);assert.equal(ui['map-links-toggle'].attrs['aria-pressed'],'false');
    ui['map-links-toggle'].listeners.click();assert.equal(paths().length,ranked.length);
    ui.measure.value='coverage';ui.measure.listeners.change();
    assert.equal(ui['map-play'].hidden,true);assert.equal(paths().length,0);
    assert.match(ui['map-legend-caption'].textContent,/fixed 0–100%/);
    assert.equal(ui['map-legend-values'].children.length,6);
    const low=await fixture({reduced:true});low.ui['map-play'].listeners.click();
    assert(!low.ui['map-arcs'].children.some(c=>c.attrs.class==='map-pulses'));
  }
  const sample={generated:data.generated,wazuh:{total_7d:7,top_src:[['192.0.2.31',5],['192.0.2.32',2]]},
    enrich_meta:{'192.0.2.31':{country:'TW'},'192.0.2.32':{country:'HK'}}};
  const {ui:g}=await fixture({snapshot:sample});
  const mapPath=code=>g['map-land'].children[world.land.findIndex(([k])=>k===code)];
  assert.match(g['map-status'].textContent,/Mapped 1 of 1/);
  assert.equal(g['map-selection-title'].textContent,'China');
  assert.equal(g['map-selection-count'].textContent,'7 bucket alerts');
  assert.match(mapPath('CN').attrs.class,/map-picked/);
  assert.match(mapPath('TW').attrs.class,/map-picked-member/);
  assert.equal(g['china-lens'].hidden,false);
  assert.match(g['inset-land'].children.find(e=>e.attrs['data-region']==='TW').attrs.class,/inset-selected/);
  assert.deepEqual(g['inset-labels'].children.filter(e=>e.tag==='circle').map(e=>e.attrs['data-region']),['TW','HK']);
  assert(g['map-points'].children.some(e=>e.attrs['data-region']==='TW'&&e.attrs.class==='map-member-ring'));
  g['country-grouping'].value='separate';g['country-grouping'].listeners.change();
  assert.match(g['map-status'].textContent,/Mapped 1 of 2/);
  assert.equal(g['map-selection-title'].textContent,'Taiwan');
  assert.equal(g['map-selection-count'].textContent,'5 bucket alerts');
  assert.equal(g['china-lens'].hidden,true);
  assert.doesNotMatch(mapPath('CN').attrs.class,/map-picked/);
  assert.match(mapPath('TW').attrs.class,/map-picked/);
  assert.equal(g['map-arcs'].children.filter(e=>e.tag==='path').length,0);
  g.measure.value='coverage';g.measure.listeners.change();
  assert.match(mapPath('TW').attrs.class,/map-zero/);
  assert.doesNotMatch(mapPath('US').attrs.class,/map-zero/);
  mapPath('TW').listeners.click();assert.equal(g['map-selection-count'].textContent,'0.0%');
  const unavailable=await fixture({shape:null});assert.match(unavailable.ui['map-status'].textContent,/outline unavailable/);
  assert.equal(unavailable.ui.workspace.hidden,false);
  const unsafe={...world,land:[[null,'<svg>'],...world.land.slice(1)]};
  assert.match((await fixture({shape:unsafe})).ui['map-status'].textContent,/outline unavailable/);
  console.log('Country pulse map: real scope, local outline, playback, reduced motion and graceful fallback OK');
})().catch(error=>{console.error(error);process.exitCode=1;});
