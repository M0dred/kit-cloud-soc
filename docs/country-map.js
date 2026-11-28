"use strict";
// Each animated link represents one published aggregate group, not an event or path.
function createCountryMap(onSelect) {
  const el=id=>document.getElementById(id), anchorCode=code=>/^[A-Z]{2}$/.test(code);
  const land=el("map-land"), links=el("map-arcs"), points=el("map-points");
  const picker=el("map-focus"), play=el("map-play"), toggler=el("map-links-toggle");
  let world=null, groups=[], mode="alerts", active=null, showLinks=false, timer=null, view="snapshot", freshUntil=0;
  // Public Natural Earth 5.1.2 1:10m label point, not source or sensor coordinates.
  const hongKong=[564.0,148.1];
  const add=(parent,tag,attrs)=>{
    const node=document.createElementNS("http://www.w3.org/2000/svg",tag);
    for (const [k,v] of Object.entries(attrs)) node.setAttribute(k,String(v));
    parent.appendChild(node);return node;
  };
  const createPoint=point=>Array.isArray(point) && point.length===2 && point.every(Number.isFinite) &&
    point[0]>=15 && point[0]<=688 && point[1]>=8 && point[1]<=315;
  function geometry(doc) {
    if (doc?.schema_version!==1 || !Array.isArray(doc.land) || doc.land.length<100 || doc.land.length>250 ||
        !doc.anchors || typeof doc.anchors!=="object" || Array.isArray(doc.anchors)) throw Error("invalid outline");
    const entries=Object.entries(doc.anchors);
    if (entries.length<100 || entries.length>250 || entries.some(([code,xy])=>!anchorCode(code)||!createPoint(xy))) throw Error("invalid map points");
    const anchors=new Map(entries);
    for (const row of doc.land) {
      if (!Array.isArray(row) || row.length!==2 || !(row[0]===null || anchorCode(row[0])) ||
          typeof row[1]!=="string" || row[1].length>70000 || !/^M[MLZ\d.,-]+Z$/.test(row[1])) throw Error("invalid land path");
    }
    return {land:doc.land,anchors};
  }
  const visible=()=>world?groups.filter(g=>world.anchors.has(g.code)):[];
  const summaryMetric=()=>mode==="coverage"?"fresh lookup coverage":mode==="rows"?"source rows":"reported bucket alerts";
  const shade=(value,max)=>value===0?"map-zero":`map-v${Math.min(4,Math.ceil(4*value/max))}`;
  function legend(max,shown) {
    const list=el("map-legend-values"), caption=el("map-legend-caption");
    list.replaceChildren();
    const item=(cls,label)=>{
      const li=document.createElement("li"), swatch=document.createElement("i"), txt=document.createElement("span");
      swatch.className=`map-swatch ${cls}`;swatch.setAttribute("aria-hidden","true");txt.textContent=label;
      li.appendChild(swatch);li.appendChild(txt);list.appendChild(li);
    };
    const coverage=mode==="coverage";
    caption.textContent=!shown?"No plotted observations.":coverage?"Fresh lookup coverage · fixed 0–100% scale":`${mode==="rows"?"Source count":"Alert volume"} · fill scale set by the largest mapped original label in this batch`;
    item("map-unobserved","Not in mapped subset");
    if (!shown) return;
    item("map-zero",coverage?"0% fresh coverage":"0 in selected metric");
    let previous=0;
    for (let i=1;i<=4;i+=1) {
      const upper=coverage?25*i:Math.floor(max*i/4);
      if (upper<=previous) continue;
      item(`map-v${i}`,coverage?`>${previous}–${upper}%`:`${(previous+1).toLocaleString()}–${upper.toLocaleString()}`);
      previous=upper;
    }
  }
  function inset(selected) {
    const lens=el("china-lens"), shapes=el("inset-land"), annotations=el("inset-labels");
    lens.hidden=!(selected?.code==="CN" && selected.members?.includes("TW") && world.anchors.has("TW"));
    shapes.replaceChildren();annotations.replaceChildren();
    if (lens.hidden) return;
    for (const [code,d] of world.land) {
      if (!["CN","TW","PH","VN","JP"].includes(code)) continue;
      add(shapes,"path",{d,class:`inset-land${code==="CN"||code==="TW"?" inset-selected":""}${selected.native.has(code)?" inset-observed":""}`,"fill-rule":"evenodd","data-region":code});
    }
    const mark=(code,p,dx,dy)=>{
      const [x,y]=p, lx=x+dx,ly=y+dy;
      add(annotations,"path",{d:`M ${x} ${y} L ${lx} ${ly-.6}`,class:"inset-leader"});
      add(annotations,"circle",{cx:x,cy:y,r:.75,class:"inset-dot","data-region":code});
      const text=add(annotations,"text",{x:lx,y:ly,class:"inset-label","text-anchor":"middle"});text.textContent=code;
    };
    mark("TW",world.anchors.get("TW"),7,-5);
    mark("HK",hongKong,-7,5);
  }
  function stop() {
    if (timer!==null) clearInterval(timer);
    timer=null;play.textContent="Play pulse";
  }
  function draw() {
    if (!world) return;
    globe?.update(groups,mode,active,view==="live"?freshUntil:0);
    const shown=visible(), labels=new Map(shown.map(row=>[row.code,row]));
    const shades=new Map(shown.flatMap(row=>(row.members||[row.code]).map(code=>[code,row])));
    const coverage=mode==="coverage", inGlobe=Boolean(globe?.visible()), showPulse=showLinks&&!coverage&&view==="snapshot"&&!inGlobe;
    const highlight=view==="live"&&Date.now()<freshUntil&&!globalThis.matchMedia?.("(prefers-reduced-motion: reduce)")?.matches;
    const geometryCodes=new Set(world.land.map(([code])=>code));
    const max=coverage?100:Math.max(0,...shown.flatMap(g=>[...g.native].filter(([code])=>geometryCodes.has(code)).map(([,v])=>v)));
    const denominator=Math.max(1,max), groupDenominator=coverage?100:Math.max(1,...shown.map(g=>g.value));
    el("country-map").setAttribute("viewBox",showPulse?"0 0 896 354":"0 0 705 354");
    el("map-destination").setAttribute("class",showPulse?"":"map-hidden");
    land.replaceChildren();links.replaceChildren();points.replaceChildren();legend(max,shown.length);
    for (const [code,d] of world.land) {
      const g=shades.get(code), v=g?.native.get(code);
      const band=g?`${Number.isFinite(v)?` ${shade(v,denominator)}`:""} map-selectable`:"";
      const picked=g && g.code===active;
      const shape=add(land,"path",{d,class:`map-country${band}${picked?" map-picked":""}${picked&&g.code!==code?" map-picked-member":""}`,
        "fill-rule":"evenodd","data-region":code??""});
      if (g) shape.addEventListener("click",()=>choose(g.code,true));
    }
    const order=[...shown].sort((a,b)=>Number(a.code===active)-Number(b.code===active));
    if (showPulse) for (const g of order) {
      const [x,y]=world.anchors.get(g.code), selected=g.code===active;
      const bendY=Math.max(22,y-32-(725-x)*.12);
      const d=`M ${x} ${y} C ${Math.round((x+725)/2)} ${bendY} 670 193 725 193`;
      const width=(.8+4*Math.sqrt(g.value/groupDenominator)).toFixed(2);
      add(links,"path",{d,class:selected?"map-link-active":"map-link","stroke-width":width});
      if (selected && timer!==null && !globalThis.matchMedia?.("(prefers-reduced-motion: reduce)").matches) {
        const dot=add(links,"circle",{r:4,class:"map-pulses"});
        add(dot,"animateMotion",{path:d,dur:"1.5s",repeatCount:"indefinite"});
      }
    }
    for (const g of order) {
      const [x,y]=world.anchors.get(g.code), r=2.5+3.2*Math.sqrt(g.value/groupDenominator), selected=g.code===active;
      if(highlight&&g.value>0)add(points,"circle",{cx:x,cy:y,r:r+3,class:"map-live-ring"});
      add(points,"circle",{cx:x,cy:y,r,class:`map-dot${selected?" map-dot-focus":""}`});
      const hit=add(points,"circle",{cx:x,cy:y,r:r+3,class:"map-dot-hit"});
      const title=add(hit,"title",{});title.textContent=mode==="coverage"?`${g.label}: ${g.countLabel}`:`${g.label}: ${g.countLabel} ${summaryMetric()}`;
      hit.addEventListener("click",()=>choose(g.code,true));
    }
    play.hidden=coverage||view!=="snapshot"||inGlobe;play.disabled=shown.length===0;
    toggler.hidden=view!=="snapshot"||inGlobe;toggler.disabled=coverage;
    const selected=groups.find(g=>g.code===active), excluded=groups.length-shown.length;
    inset(selected);
    if (!el("china-lens").hidden) {
      const [x,y]=world.anchors.get("TW");
      add(points,"circle",{cx:x,cy:y,r:5,class:"map-member-ring","data-region":"TW"});
    }
    if (selected && labels.has(active)) {
      const [x,y]=world.anchors.get(active);
      const label=add(points,"text",{x,y:Math.max(19,y-11),class:"map-active-label","text-anchor":x>585?"end":"middle"});
      label.textContent=selected.label;
    }
    const excludedNote=excluded?` ${excluded} group${excluded===1?"":"s"} not plotted (unknown label or no outline point); see the ${view==="replay"?"country selector":"table"}.`:"";
    el("map-status").textContent=`Mapped ${shown.length} of ${groups.length} published country groups.${excludedNote}`;
  }
  function choose(code,notify) {
    stop();active=code;picker.value=code??"";
    if (notify) onSelect(code);
    draw();
  }
  picker.addEventListener("change",()=>choose(picker.value,true));
  toggler.addEventListener("click",()=>{showLinks=!showLinks;toggler.setAttribute("aria-pressed",String(showLinks));draw();});
  play.addEventListener("click",()=>{
    if (timer!==null) {stop();draw();return;}
    const ranked=visible();if (!ranked.length || mode==="coverage" || view!=="snapshot") return;
    showLinks=true;toggler.setAttribute("aria-pressed","true");
    let index=0;
    const show=()=>{active=ranked[index].code;picker.value=active;onSelect(active);draw();};
    timer=setInterval(()=>{
      index+=1;
      if (index===ranked.length) {stop();draw();return;}
      show();
    },2000);
    play.textContent="Pause pulse";show();
  });
  const globe=typeof createCountryGlobe==='function'?createCountryGlobe(code=>choose(code,true),()=>{stop();draw();}):null;
  const ready=(async()=>{
    try {
      const res=await fetch("world-map.json",{cache:"force-cache"});if (!res.ok) throw Error("outline unavailable");
      world=geometry(await res.json());
      try{globe?.setWorld(world);}catch(_){/* The flat map still works without a globe. */}
      el("map-controls").hidden=false;el("map-figure").hidden=false;draw();
    } catch (_) {el("map-status").textContent="Map outline unavailable. The country table and rankings still use the published batch.";}
  })();
  return {ready, update(rows,metric,code,options={}){
    groups=rows;mode=metric;view=options.view||"snapshot";if(options.fresh)freshUntil=Date.now()+1400;
    else freshUntil=0;
    picker.replaceChildren();
    for (const g of groups) {
      const option=document.createElement("option");option.value=g.code;option.textContent=g.label;picker.appendChild(option);
    }
    picker.disabled=groups.length===0;
    choose(code,false);
  }, focus:code=>choose(code,false)};
}
