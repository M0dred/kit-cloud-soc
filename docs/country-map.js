"use strict";
// Each animated link represents one published aggregate group, not an event or path.
function createCountryMap(onSelect) {
  const el=id=>document.getElementById(id), anchorCode=code=>/^[A-Z]{2}$/.test(code);
  const land=el("map-land"), links=el("map-arcs"), points=el("map-points");
  const picker=el("map-focus"), play=el("map-play"), toggler=el("map-links-toggle");
  let world=null, groups=[], mode="alerts", active=null, showLinks=true, timer=null;
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
  const summaryMetric=()=>mode==="rows"?"source rows":"reported bucket alerts";
  function stop() {
    if (timer!==null) clearInterval(timer);
    timer=null;play.textContent="Play highlights";
  }
  function draw() {
    if (!world) return;
    const shown=visible(), labels=new Map(shown.map(row=>[row.code,row]));
    const shades=new Map(shown.flatMap(row=>(row.members||[row.code]).map(code=>[code,row])));
    const max=Math.max(1,...shown.map(g=>g.value));
    land.replaceChildren();links.replaceChildren();points.replaceChildren();
    for (const [code,d] of world.land) {
      const g=shades.get(code), shade=g?` map-v${Math.max(1,Math.ceil(4*g.value/max))}`:"";
      add(land,"path",{d,class:`map-country${shade}${g && g.code===active?" map-picked":""}`,"fill-rule":"evenodd"});
    }
    const order=[...shown].sort((a,b)=>Number(a.code===active)-Number(b.code===active));
    if (showLinks) for (const g of order) {
      const [x,y]=world.anchors.get(g.code), selected=g.code===active;
      const bendY=Math.max(22,y-32-(725-x)*.12);
      const d=`M ${x} ${y} C ${Math.round((x+725)/2)} ${bendY} 670 193 725 193`;
      const width=(.8+4*Math.sqrt(g.value/max)).toFixed(2);
      add(links,"path",{d,class:selected?"map-link-active":"map-link","stroke-width":width});
      if (selected && timer!==null && !globalThis.matchMedia?.("(prefers-reduced-motion: reduce)").matches) {
        const dot=add(links,"circle",{r:4,class:"map-pulses"});
        add(dot,"animateMotion",{path:d,dur:"1.5s",repeatCount:"indefinite"});
      }
    }
    for (const g of order) {
      const [x,y]=world.anchors.get(g.code), r=2.5+3.2*Math.sqrt(g.value/max), selected=g.code===active;
      add(points,"circle",{cx:x,cy:y,r,class:`map-dot${selected?" map-dot-focus":""}`});
      const hit=add(points,"circle",{cx:x,cy:y,r:r+3,class:"map-dot-hit"});
      const title=add(hit,"title",{});title.textContent=`${g.label}: ${g.value.toLocaleString()} ${summaryMetric()}`;
      hit.addEventListener("click",()=>choose(g.code,true));
    }
    play.disabled=shown.length===0;
    const selected=groups.find(g=>g.code===active), excluded=groups.length-shown.length;
    if (selected && labels.has(active)) {
      const [x,y]=world.anchors.get(active);
      const label=add(points,"text",{x,y:Math.max(19,y-11),class:"map-active-label","text-anchor":x>585?"end":"middle"});
      label.textContent=selected.label;
    }
    const excludedNote=excluded?` ${excluded} group${excluded===1?"":"s"} not plotted (unknown label or no outline point); see the table.`:"";
    const focus=selected?` Selected: ${selected.label} · ${selected.value.toLocaleString()} ${summaryMetric()}${labels.has(selected.code)?".":" (not plotted)."}`:"";
    el("map-status").textContent=`Mapped ${shown.length} of ${groups.length} published country groups.${excludedNote}${focus}`;
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
    const ranked=visible();if (!ranked.length) return;
    let index=0;
    const show=()=>{active=ranked[index].code;picker.value=active;onSelect(active);draw();};
    timer=setInterval(()=>{
      index+=1;
      if (index===ranked.length) {stop();draw();return;}
      show();
    },2000);
    play.textContent="Pause highlights";show();
  });
  const ready=(async()=>{
    try {
      const res=await fetch("world-map.json",{cache:"force-cache"});if (!res.ok) throw Error("outline unavailable");
      world=geometry(await res.json());el("map-controls").hidden=false;el("map-figure").hidden=false;draw();
    } catch (_) {el("map-status").textContent="Map outline unavailable. The country table and rankings still use the published batch.";}
  })();
  return {ready, update(rows,metric,code){
    groups=rows;mode=metric;picker.replaceChildren();
    for (const g of groups) {
      const option=document.createElement("option");option.value=g.code;option.textContent=g.label;picker.appendChild(option);
    }
    picker.disabled=groups.length===0;
    choose(code,false);
  }, focus:code=>choose(code,false)};
}
