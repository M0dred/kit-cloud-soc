'use strict';
const assert=require('node:assert/strict');const fs=require('node:fs');const path=require('node:path');const vm=require('node:vm');
const dir=path.join(__dirname,'../docs'), code=fs.readFileSync(path.join(dir,'country-globe.js'),'utf8');
const scope=vm.createContext({});vm.runInContext(code,scope);const g=vm.runInContext('GlobeGeometry',scope),near=(a,b)=>assert(Math.abs(a-b)<1e-8);
near(g.angles([351.8,193])[0],0);near(g.angles([351.8,193])[1],0);
for(const [lon,lat] of [[0,0],[114,25],[-179,-70]]){
 const p=g.camera(lon,lat),f=p(g.unit(lon,lat)),b=p(g.unit(lon+180,-lat));
 near(f[0],0);near(f[1],0);near(f[2],1);near(b[2],-1);
}
const c=g.limb([.6,.4,.6],[.6,-.4,-.6]);near(c[2],0);near(Math.hypot(c[0],c[1]),1);
assert.equal(g.wrap(184),-176);assert.equal(g.lines('M17,23L18,26L19,27ZM30,32L35,40L38,32Z').length,2);
const world=JSON.parse(fs.readFileSync(path.join(dir,'world-map.json'),'utf8'));
assert(world.land.every(([,d])=>g.lines(d).every(r=>r.length>=3&&r.every(p=>p.every(Number.isFinite)))));
const marks=[],el={},ops={};let frame=null,reduced=false,hidden=false;
for(const name of ['strokeText','stroke','fill','clip','clearRect','fillText','setTransform','save','restore','moveTo','lineTo','beginPath'])ops[name]=()=>{};
Object.assign(ops,{arc:(...args)=>marks.push(args),createRadialGradient:()=>({addColorStop(){}}),measureText:s=>({width:s.length*7})});
function element(id){return el[id]??={hidden:['globe-stage','globe-toggle'].includes(id),listeners:{},getContext:()=>ops,
 addEventListener(k,f){this.listeners[k]=f;},setAttribute(k,v){this[k]=v;},getBoundingClientRect:()=>({width:600,height:450,left:0,top:0})};}
const mockDoc={get hidden(){return hidden;},getElementById:element},docContext={document:mockDoc,requestAnimationFrame:f=>{frame=f;return 1;},matchMedia:()=>({get matches(){return reduced;}})};
const s=vm.createContext(docContext);vm.runInContext(code,s);const view=vm.runInContext('createCountryGlobe(()=>{},()=>{})',s);
view.setWorld({land:[],anchors:new Map([['CN',[351.8+48*1.86,151]],['US',[351.8-132*1.86,235]],['TW',[600,140]]])});
view.update([{code:'CN',label:'China',members:['CN','TW'],native:new Map([['CN',30]])},{code:'US',label:'US',members:['US'],native:new Map([['US',10]])}],'alerts','CN',0);
element('globe-toggle').listeners.click();let draw=frame;frame=null;draw();
assert.equal(marks.filter(p=>p[2]<12).length,1,'only the visible observed original label has a dot');
assert(element('flat-map').hidden);assert.match(element('globe-legend').textContent,/original country labels/);
marks.length=0;view.update([{code:'CN',label:'China',members:['CN'],native:new Map([['CN',30]])}],'alerts','CN',Date.now()+900);
draw=frame;frame=null;draw();assert(marks.some(p=>p[2]>12&&p[2]<50));assert(frame);
reduced=true;marks.length=0;draw=frame;frame=null;draw();assert(!marks.some(p=>p[2]>12&&p[2]<50));assert.equal(frame,null);
hidden=true;element('globe-toggle').listeners.click();assert(!element('flat-map').hidden);
console.log('Country globe: real local geometry, limb/back-side, observed labels only, published-batch ring and reduced motion');
