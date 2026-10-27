// Offline DOM smoke test. No browser, API calls, credentials or network required.
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..');
const page = fs.readFileSync(path.join(root, 'docs/index.html'), 'utf8');
const script = fs.readFileSync(path.join(root, 'docs/app.js'), 'utf8');
const data = JSON.parse(fs.readFileSync(path.join(root, 'docs/data.json'), 'utf8'));
assert(!script.includes('innerHTML'), 'Dynamic HTML insertion is forbidden');
assert(page.includes("script-src 'self'"), 'Page must have a restrictive script CSP');
assert(page.includes('src="app.js"'), 'External script must be loaded');
class Element {
  constructor() {this.children=[];this.listeners={};this.style={};this.hidden=false;this.value='';this._text='';}
  set textContent(value) {this._text=String(value);this.children=[];}
  get textContent(){return this._text;}
  set innerHTML(_){throw new Error('Unsafe innerHTML used');}
  appendChild(node){this.children.push(node);return node;}
  replaceChildren(...children){this.children=[...children];}
  setAttribute(name,value){this[name]=value;}
  addEventListener(name,fn){this.listeners[name]=fn;}
}
const ids = [...page.matchAll(/\bid="([^"]+)"/g)].map(x=>x[1]);
assert.equal(ids.length,new Set(ids).size,'HTML IDs must be unique');
const elements = Object.fromEntries(ids.map(id=>[id,new Element()]));
const document={getElementById(id){assert(elements[id],`missing element ${id}`);return elements[id];},
  createElement(){return new Element();}};
const healthy={schema_version:1,state:'ok',last_attempt_utc:data.generated};
const timestamp=Date.parse(data.generated.replace(' UTC','Z').replace(' ','T'));
const FreshDate=class extends Date {static now(){return timestamp+3600000;}};
const sandbox={document,console,Date:FreshDate,
  fetch:async url=>({ok:true,json:async()=>url==='status.json'?healthy:data})};
vm.runInNewContext(script,sandbox,{timeout:2000});
setTimeout(()=>{
  try {
    assert.match(elements.gen.textContent,/Generated/);
    assert.equal(elements['status-pill'].textContent,'LAST RUN OK');
    assert.equal(elements.kpis.children.length,4);
    assert.match(elements['selection-explain'].textContent,/MISP IP attributes.*stricter public list/);
    assert.equal(elements.src.children.length,2,'Semantic thead/tbody missing');
    const rows=elements.src.children[1].children;
    const button=rows[0]?.children[0]?.children[0];
    assert(button?.listeners?.click,'No keyboard-focusable source button');
    button.listeners.click();
    assert.equal(elements['ioc-detail'].hidden,false);
    assert(elements['ioc-detail'].children.length>3);
    assert(!JSON.stringify(data).includes('samples_by_source'),'Private evidence leaked into public JSON');
    assert(elements['day-values'].children.length>0,'Visible UTC daily numbers missing');
    const stale=Object.fromEntries(ids.map(id=>[id,new Element()]));
    const staleDoc={getElementById(id){assert(stale[id]);return stale[id];},createElement(){return new Element();}};
    const FakeDate=class extends Date {static now(){return timestamp+48*3600000;}};
    vm.runInNewContext(script,{document:staleDoc,console,Date:FakeDate,
      fetch:async url=>({ok:true,json:async()=>url==='status.json'?healthy:data})},{timeout:2000});
    setTimeout(()=>{
      try {assert.equal(stale['status-pill'].textContent,'STALE SNAPSHOT');
        const degraded=Object.fromEntries(ids.map(id=>[id,new Element()]));
        const doc={getElementById(id){assert(degraded[id]);return degraded[id];},createElement(){return new Element();}};
        const RecentDate=class extends Date {static now(){return timestamp+3600000;}};
        vm.runInNewContext(script,{document:doc,console,Date:RecentDate,
          fetch:async url=>({ok:true,json:async()=>url==='status.json'?{...healthy,state:'degraded'}:data})},{timeout:2000});
        setTimeout(()=>{
          try{assert.equal(degraded['status-pill'].textContent,'PIPELINE DEGRADED');
            console.log('Public UI healthy/stale/degraded smoke tests OK');}
          catch(error){console.error(error);process.exitCode=1;}
        },25);}
      catch(error){console.error(error);process.exitCode=1;}
    },25);
  } catch(error){console.error(error);process.exitCode=1;}
},25);
