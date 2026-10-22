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
const sandbox={document,console,fetch:async()=>({ok:true,json:async()=>data})};
vm.runInNewContext(script,sandbox,{timeout:2000});
setTimeout(()=>{
  try {
    assert.match(elements.gen.textContent,/Generated/);
    assert.notEqual(elements['status-pill'].textContent,'LOADING');
    assert.equal(elements.kpis.children.length,4);
    assert(elements.src.children.length>=2,'Source table missing');
    const row=elements.src.children.find(x=>x.listeners.click);
    assert(row,'No accessible source row');
    row.listeners.click();
    assert.equal(elements['ioc-detail'].hidden,false);
    assert(elements['ioc-detail'].children.length>3);
    assert(!JSON.stringify(data).includes('samples_by_source'),'Private evidence leaked into public JSON');
    console.log('Public UI smoke test OK');
  } catch(error){console.error(error);process.exitCode=1;}
},25);
