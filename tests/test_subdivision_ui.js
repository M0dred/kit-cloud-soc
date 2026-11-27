'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const {webcrypto}=require('node:crypto');
const docs=path.resolve(__dirname,'../docs');
const html=fs.readFileSync(path.join(docs,'flow.html'),'utf8');
const profile=fs.readFileSync(path.join(docs,'subdivisions.js'),'utf8');
const app=fs.readFileSync(path.join(docs,'flow.js'),'utf8');
const data=fs.readFileSync(path.join(docs,'data.json'));
const aggregate=JSON.parse(fs.readFileSync(path.join(docs,'subdivisions.json'),'utf8'));
const ids=[...html.matchAll(/\bid="([^"]+)"/g)].map(([,id])=>id);
assert.equal(ids.length,new Set(ids).size);
assert(html.indexOf('src="subdivisions.js"')<html.indexOf('src="flow.js"'));
assert.match(html,/No verified subdivision profile/);
assert.match(html,/https:\/\/db-ip\.com\//);
class Element {
  constructor(tag){this.tag=tag;this.children=[];this.attrs={};this.listeners={};this.hidden=true;this.value='';this.textContent='';}
  appendChild(el){this.children.push(el);}
  replaceChildren(){this.children=[];}
  setAttribute(k,v){this.attrs[k]=v;}
  addEventListener(k,fn){this.listeners[k]=fn;}
  scrollIntoView(){this.scrolled=true;}
}
const text=node=>[node.textContent,...node.children.map(text)].join(' ');
async function run(raw,sidecar,hash='#subdivisions') {
  const ui=Object.fromEntries(ids.map(id=>[id,new Element('div')]));
  const now=Date.parse(JSON.parse(raw).generated.replace(' UTC','Z').replace(' ','T'))+3600000;
  const Clock=class extends Date {static now(){return now;}};
  const calls=[];
  const ctx=vm.createContext({TextDecoder,crypto:webcrypto,Date:Clock,location:{hash},
    document:{getElementById:id=>ui[id],createElement:tag=>new Element(tag),createElementNS:(ns,tag)=>new Element(tag)},
    fetch:async url=>{calls.push(url);assert(['data.json','status.json','subdivisions.json'].includes(url));
      return {ok:url!=='status.json',arrayBuffer:async()=>raw.buffer.slice(raw.byteOffset,raw.byteOffset+raw.byteLength),json:async()=>sidecar};}});
  vm.runInContext(profile,ctx,{timeout:2000});await vm.runInContext(app,ctx,{timeout:2000});
  await new Promise(resolve=>setImmediate(resolve));
  assert.deepEqual(calls,['data.json','status.json','subdivisions.json']);
  return ui;
}
(async()=>{
  const ui=await run(data,aggregate);
  assert.equal(ui.workspace.hidden,false);
  assert.equal(ui.subdivisions.open,true);assert.equal(ui.subdivisions.scrolled,true);
  const snapshot=JSON.parse(data), result=text(ui['subdivision-profile']);
  if(aggregate.countries){
    assert.match(ui['subdivision-status'].textContent,/minimum 3 distinct source rows/);
    assert(snapshot.wazuh.top_src.every(([ip])=>!result.includes(ip)));
    for(const [cc,group] of Object.entries(aggregate.countries)){
      if(!group.subdivisions.length) continue;
      // Expose the associated aggregate by selecting its original country row.
      const names=new Intl.DisplayNames(['en'],{type:'region'});
      if(['TW','HK'].includes(cc)) continue;
      const button=ui['country-rows'].children.map(tr=>tr.children[0].children[0]).find(btn=>btn.textContent===names.of(cc));
      if(!button) continue;
      button.listeners.click();
      for(const cell of group.subdivisions) assert(text(ui['subdivision-profile']).includes(cell.name));
    }
    const bad=structuredClone(aggregate);
    for(const v of Object.values(bad.countries)){v.withheld_rows+=1;}
    assert.match((await run(data,bad))['subdivision-status'].textContent,/do not reconcile/);
  } else assert.match(ui['subdivision-status'].textContent,/No verified/);
  const altered=Buffer.concat([data,Buffer.from(' ')]), stale=await run(altered,aggregate);
  assert.equal(stale.workspace.hidden,false);
  assert.match(stale['subdivision-status'].textContent,/exact batch/);
  assert.equal(stale['subdivision-profile'].children.length,0);
  console.log('Subdivision layer: exact snapshot binding, reconciliation, aggregate-only UI and stale fallback OK');
})().catch(e=>{console.error(e);process.exitCode=1;});
