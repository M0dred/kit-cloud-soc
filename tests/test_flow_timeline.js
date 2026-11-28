'use strict';
const assert=require('node:assert/strict');const vm=require('node:vm');const fs=require('node:fs');const path=require('node:path');
const dir=path.join(__dirname,'../docs'),read=n=>fs.readFileSync(path.join(dir,n),'utf8');
const early={batch_utc:'2026-11-25 06:03 UTC',countries:[['CN',4,29],['unknown',1,2]]};
const late={batch_utc:'2026-11-26 12:01 UTC',countries:[['TW',3,18],['US',2,9]]};
const raw={schema_version:1,frames:[early,late]};
async function check(reduced=false,offline=false){
 const ui={},renders=[],loads=[];let tick;
 const document={getElementById:id=>ui[id]??={value:'',listeners:{},addEventListener(k,v){this.listeners[k]=v;},setAttribute(k,v){this[k]=v;}}};
 const context=vm.createContext({document,renders,raw,early,late,fetch:async f=>{loads.push(f);return {ok:!offline,json:async()=>raw};},
   matchMedia:()=>({matches:reduced}),setInterval:f=>{tick=f;return 1;},clearInterval:()=>{tick=null;}});
 vm.runInContext(read('public-view.js')+'\n'+read('flow-timeline.js'),context);
 const checkParse=v=>{context.input=v;return vm.runInContext('FlowTimeline.parse(input,new Set(["CN","TW","US"]))',context);};
 assert.equal(checkParse(raw).length,2);
 for(const bad of [{...raw,addresses:[]},{...raw,frames:[late,early]},{...raw,frames:[{...early,countries:[['CN',21,0]]}]},
  {...raw,frames:[{...early,countries:[['192.0.2.11',1,5]]}]},{...raw,frames:[{...early,sensor:'any'}]}])assert.throws(()=>checkParse(bad));
 const control=vm.runInContext('FlowTimeline.connect({known:new Set(["CN","TW","US"]),render:(...x)=>renders.push(x)})',context);
 assert.equal(control.mode(),'snapshot');ui['map-view'].value='live';ui['map-view'].listeners.change();assert.equal(renders.at(-1)[0],'live');assert.equal(loads.length,0);
 ui['map-view'].value='replay';ui['map-view'].listeners.change();await new Promise(setImmediate);
 assert.deepEqual(loads,['map-replay.json']);assert.equal(ui['replay-controls'].hidden,false);
 if(offline){assert.equal(renders.at(-1)[1],null);control.record(early);assert.equal(renders.at(-1)[1],early);assert.match(ui['map-view-note'].textContent,/Archive unavailable/);return;}
 assert.equal(renders.at(-1)[1],early);assert.equal(ui['replay-play'].hidden,reduced);
 ui['replay-play'].listeners.click();if(!reduced){assert.equal(typeof tick,'function');tick();assert.equal(renders.at(-1)[1],late);assert.equal(tick,null);}
 else {assert.equal(tick,undefined);ui['replay-next'].listeners.click();assert.equal(renders.at(-1)[1],late);}
 assert.match(ui['replay-stamp'].textContent,/11-26 12:01 UTC/);
 ui['map-view'].value='snapshot';ui['map-view'].listeners.change();assert.equal(ui['replay-controls'].hidden,true);
 assert(vm.runInContext('FlowTimeline.eligible({generated:late.batch_utc},{state:"ok",last_attempt_utc:late.batch_utc},true)',context));
 assert(!vm.runInContext('FlowTimeline.eligible({generated:late.batch_utc},{state:"degraded",last_attempt_utc:late.batch_utc},true)',context));
 assert(!vm.runInContext('FlowTimeline.eligible({generated:late.batch_utc,public_revision:{}},{state:"ok",last_attempt_utc:late.batch_utc},true)',context));
}
Promise.all([check(),check(true),check(false,true)]).then(()=>console.log('Flow timeline: archive validation, stepping, autoplay, reduced motion, live and unavailable branches')).catch(e=>{console.error(e);process.exitCode=1;});
