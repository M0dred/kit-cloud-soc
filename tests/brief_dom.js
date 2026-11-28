'use strict';
const fs=require('node:fs');const vm=require('node:vm');const path=require('node:path');
const docs=path.resolve(__dirname,'../docs');
const read=name=>fs.readFileSync(path.join(docs,name),'utf8');
const markup=read('index.html');
const snapshot=JSON.parse(read('data.json'));
const stamp=s=>Date.parse(s.replace(' UTC','Z').replace(' ','T'));
async function brief(data,report,{now=stamp(snapshot.generated)+3600000,mobile=false,classic=false}={}){
  let document;
  class Element {
    constructor(tag='div'){this.tag=tag;this.children=[];this.listeners={};this.hidden=false;this.value='';this._text='';this.attrs={};this.parentNode=null;}
    get textContent(){return this._text+this.children.map(x=>x.textContent).join('');}
    set textContent(t){this.replaceChildren();this._text=String(t);}
    set innerHTML(_){throw Error('Unsafe DOM write');}
    appendChild(x){x.remove();this.children.push(x);x.parentNode=this;return x;}
    remove(){if(this.parentNode){const list=this.parentNode.children;list.splice(list.indexOf(this),1);this.parentNode=null;}}
    replaceChildren(){this.children.forEach(c=>{c.parentNode=null;});this.children=[];this._text='';}
    insertAdjacentElement(where,x){if(where!=='afterend')throw Error('Fixture expects inline disclosure');x.remove();const p=this.parentNode;p.children.splice(p.children.indexOf(this)+1,0,x);x.parentNode=p;}
    setAttribute(k,v){this.attrs[k]=String(v);this[k]=v;}
    addEventListener(k,v){this.listeners[k]=v;}
    focus(){document.activeElement=this;}
    scrollIntoView(){this.scrolled=true;}
  }
  const page=classic?read('classic.html'):markup;
  const ids=[...page.matchAll(/\bid="([^"]+)"/g)].map(([,id])=>id);
  const ui=Object.fromEntries(ids.map(id=>[id,new Element()]));
  ui['detail-dock'].appendChild(ui['ioc-detail']);ui['ioc-detail'].hidden=true;
  const calls=[];
  document={activeElement:null,body:{dataset:{view:classic?'classic':'brief'}},createElement:tag=>new Element(tag),createElementNS:(_,tag)=>new Element(tag),getElementById:id=>ui[id]};
  const Clock=class extends Date{static now(){return now;}};
  const feed={data,report,dataAvailable:true,reportAvailable:true};
  const ctx=vm.createContext({document,Date:Clock,matchMedia:()=>({matches:mobile}),fetch:async uri=>{
    calls.push(uri);const isData=uri==='data.json';return {ok:isData?feed.dataAvailable:feed.reportAvailable,json:async()=>isData?feed.data:feed.report};
  }});
  vm.runInContext(read('public-view.js'),ctx,{timeout:2000});vm.runInContext(read('published-refresh.js'),ctx,{timeout:2000});
  await vm.runInContext(read('app.js'),ctx,{timeout:2000});
  return {ui,calls,document,feed};
}
module.exports={read,markup,snapshot,stamp,brief};
