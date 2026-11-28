"use strict";
// GitHub Pages is a read-only projection, not a case workspace.
const byId=id=>document.getElementById(id);
const count=v=>Number.isSafeInteger(v)&&v>=0;
const metric=v=>count(v)?v.toLocaleString():"N/A";
const defang=ip=>ip.replace(/\.(?=\d+$)/,"[.]");
const validIP=ip=>typeof ip==="string"&&/^(?:\d{1,3}\.){3}\d{1,3}$/.test(ip)&&ip.split(".").every(o=>Number(o)<=255&&String(Number(o))===o);
function add(parent,tag,text,css=""){
  const el=document.createElement(tag);el.textContent=String(text);if(css)el.className=css;parent.appendChild(el);return el;
}
function svg(parent,tag,attrs){
  const el=document.createElementNS("http://www.w3.org/2000/svg",tag);
  for(const [k,v] of Object.entries(attrs)) el.setAttribute(k,String(v));
  parent.appendChild(el);return el;
}
function addHeading(table,labels,classes=[]){
  const line=add(add(table,"thead",""),"tr","");
  labels.forEach((label,i)=>add(line,"th",label,classes[i]||"").setAttribute("scope","col"));
  return add(table,"tbody","");
}
function row(table,values,classes=[]){
  const tr=add(table,"tr","");values.forEach((v,i)=>add(tr,"td",v,classes[i]||""));return tr;
}
const stateLabel=s=>({fresh:"fresh",cached:"cached; latest attempt failed",stale:"stale (>48h)",not_observed:"not observed in lookup",unknown_age:"lookup age unknown",not_queried:"not queried",rate_limited:"rate limited",lookup_failed:"lookup failed"})[s]||"unknown";
function lookupLabel(status,hasValue){
  if(status?.last_attempt==="rate_limited")return hasValue?`rate limited; ${stateLabel(status.state)}`:"rate limited; no value";
  if(status?.last_attempt==="error")return hasValue?`lookup failed; ${stateLabel(status.state)}`:"lookup failed; no value";
  if(status?.state==="not_observed")return "not observed in lookup";
  if(!hasValue&&status?.last_attempt==="ok")return "queried; no mapped value";
  return stateLabel(status?.state||"not_queried");
}
function counts(rows){
  const sum=rows.reduce((a,[,n])=>count(a)&&count(n)?a+n:NaN,0);return count(sum)?sum:null;
}
function renderCards(d,rows){
  const root=byId("kpis");root.replaceChildren();
  const volume=["All Wazuh alerts · 7d",metric(d.wazuh.total_7d),"Exact query total; not an incident count."];
  const cards=document.body?.dataset?.view==="classic"?[volume,
    ["MISP 1932 attributes",metric(d.misp?.total),"Catalog, not incidents."],
    ["VT ledger entries",metric(d.vt?.posted_total),"Local deduplication; not a verified post count."],
    ["Public watchlist",metric(d.blocklist_n),"Review before action."]]:[volume,
    ["Public source buckets",`${metric(rows.length)} of top 20`,`${metric(counts(rows))} bucket alerts in the displayed subset.`]];
  for(const [title,value,note] of cards){
    const card=add(root,"div","","card");add(card,"h2",title);add(card,"div",value,"big");add(card,"p",note,"ksub");
  }
  byId("catalog-metrics").textContent=`MISP IP attributes: ${metric(d.misp?.total)} · Public watchlist: ${metric(d.blocklist_n)} · VT deduplication entries (not a verified post count): ${metric(d.vt?.posted_total)}.`;
  const totals=count(d.misp?.total)&&count(d.blocklist_n)?`${metric(d.misp.total)} MISP IP attributes → ${metric(d.blocklist_n)} in the stricter public list. `:"MISP or watchlist count unavailable. ";
  byId("selection-explain").textContent=totals+"List requires an IDS flag, verified SSH failures and fresh corroborating context. An old IDS flag is not proof of analyst approval.";
}
function renderDaily(d){
  const rows=Array.isArray(d.wazuh?.by_day)?d.wazuh.by_day.filter(x=>Array.isArray(x)&&Number.isFinite(PublicView.utc(`${x[0]} 00:00 UTC`))).slice(0,8):[];
  const chart=byId("days"), exact=byId("day-values");chart.replaceChildren();exact.replaceChildren();
  const max=Math.max(1,...rows.map(([,v])=>count(v)?v:0));
  if(!rows.length) add(exact,"span","Daily values unavailable; do not infer zero alerts.");
  for(const [index,[day,v]] of rows.entries()){
    const edge=index===0||index===rows.length-1;
    add(exact,"span",`${day}: ${metric(v)}${edge?" (may be partial)":""}`,"day-value");
    if(!count(v)){
      const missing=add(chart,"div","","day-bin");add(missing,"span","N/A","unknown");add(missing,"span",day.slice(5));
      continue;
    }
    const bin=add(chart,"div","",`day-bin${edge?" partial":""}`);
    const height=Number((v/max*56).toFixed(2));
    const plot=svg(bin,"svg",{viewBox:"0 0 28 60",role:"img","aria-label":`${day}: ${metric(v)} alerts${edge?", may be partial":""}`});
    svg(plot,"rect",{x:4,y:58-height,width:20,height,rx:1});svg(plot,"line",{x1:2,y1:58,x2:26,y2:58});
    add(bin,"span",day.slice(5));
  }
  byId("agent-privacy").textContent="UTC · lighter bars may be partial days. Per-agent data stays private.";
}
function renderRanking(rows,meta){
  const root=byId("brief-ranking"), bins=new Map();root.replaceChildren();
  const regions=typeof Intl.DisplayNames==="function"?new Intl.DisplayNames(["en"],{type:"region",fallback:"none"}):null;
  if(counts(rows)===null) {add(root,"p","Bucket counts unavailable.","minor");return;}
  for(const [ip,n] of rows){
    const code=meta?.[ip]?.country;
    const key=["TW","HK"].includes(code)?"CN":typeof code==="string"&&/^[A-Z]{2}$/.test(code)?code:"unknown";
    bins.set(key,(bins.get(key)||0)+n);
  }
  const ranked=[...bins].sort((a,b)=>b[1]-a[1]||a[0].localeCompare(b[0]));
  if(!ranked.length){add(root,"p","No displayed source buckets.","minor");return;}
  for(const [code,n] of ranked.slice(0,6)){
    const label=code==="unknown"?"Unknown":regions?.of(code)||code;
    const line=add(root,"div","","rank-line");add(line,"span",label);
    const bar=add(line,"meter","");bar.max=Math.max(1,ranked[0][1]);bar.value=n;bar.setAttribute("aria-label",`${label}: ${metric(n)} bucket alerts`);
    add(line,"strong",metric(n));
  }
  if(ranked.length>6)add(root,"p",`${ranked.length-6} more groups in the country map.`,"minor");
}
function fillDetail(root,{ip,n,meta,member,ctx},close){
  root.replaceChildren();
  const head=add(root,"div","","detail-ctrl");add(head,"h2",`Source ${defang(ip)}`);
  const back=add(head,"button","Close");back.type="button";back.setAttribute("aria-label","Close source details");back.addEventListener("click",close);
  add(root,"p",`${metric(n)} Wazuh alerts over 7 days · source, not an incident.`);
  if(meta.country||meta.provider||meta.org) add(root,"p",`Address context: ${[meta.country, meta.provider||meta.org].filter(Boolean).join(" · ")}.`);
  const behavior=PublicView.sampleLabel(ctx.sample_behavior);
  add(root,"p",`${behavior} · sampled ${ctx.last_sample_utc||"time unavailable"}. One sample does not describe the full bucket.`);
  add(root,"p",member===true?"Present in MISP 1932 (catalog, not incident evidence).":member===false?"Not in the full MISP 1932 snapshot.":"MISP membership unavailable.");
  const list=add(root,"ul","");
  for(const [name,value,key] of [["GreyNoise",meta.gn,"gn"],["AbuseIPDB",meta.aip,"aipdb"],["OTX pulses",meta.otx,"otx"]]){
    const s=meta.sources?.[key]||{},present=value!==undefined&&value!==null&&value!=="";
    add(list,"li",`${name}: ${present?value:"no result"} · ${lookupLabel(s,present)}${s.checked_at?` · checked ${s.checked_at}`:""}`);
  }
  const next=behavior.startsWith("SSH")?"Check the actual authentication result in local logs; an SSH message is not an authentication failure.":behavior.startsWith("Web")?"Check request sequence and response outcomes; HTTP errors do not show exploitation.":"Locate the original alert and verify the asset and actual outcome locally.";
  add(root,"p",`Next local check: ${next}`);
  const refs=add(root,"div","External lookups: ","refs");
  for(const [label,prefix] of [["GreyNoise","https://viz.greynoise.io/ip/"],["AlienVault OTX","https://otx.alienvault.com/indicator/ip/"],
    ["AbuseIPDB","https://www.abuseipdb.com/check/"],["VirusTotal","https://www.virustotal.com/gui/ip-address/"],["Shodan","https://www.shodan.io/host/"],["BGP / ASN","https://bgp.he.net/ip/"]]){
    const link=add(refs,"a",label);link.href=prefix+ip;link.target="_blank";link.rel="noopener noreferrer";link.referrerPolicy="no-referrer";
  }
  add(root,"p","Each link sends the selected IP to that provider only when clicked.","dim");
}
function renderSources(d,rows){
  const table=byId("src"),dock=byId("detail-dock"),root=byId("ioc-detail"),empty=byId("detail-empty"),filter=byId("source-filter");
  const narrow=globalThis.matchMedia?.("(max-width:680px)");
  let active=null,expansion=null;
  const byButton=new WeakMap();
  function dockDetail(){
    dock.appendChild(root);expansion?.remove?.();expansion=null;
  }
  function place(){
    dockDetail();
    if(!active||!narrow?.matches) return;
    const extra=document.createElement("tr");extra.className="detail-row";
    const td=add(extra,"td","");td.colSpan=3;td.appendChild(root);
    active.tr.insertAdjacentElement("afterend",extra);expansion=extra;
  }
  function close(restore=false){
    const b=active?.button;if(b)b.setAttribute("aria-expanded","false");active=null;
    dockDetail();root.hidden=true;root.replaceChildren();empty.hidden=false;
    if(restore) b?.focus?.();
  }
  function updateCoverage(){
    const coverage=d.wazuh?.pipeline_24h_coverage||{};
    byId("pipeline-coverage").textContent=count(coverage.outside_top_alerts)
      ?`Separate 24h pipeline: top ${metric(coverage.bucket_limit)} buckets, ${metric(coverage.outside_top_alerts)} bucket alerts outside that cap. This is not the 7d source table.`
      :"Separate 24h pipeline truncation is not measured for this snapshot.";
  }
  function draw(keep=null,refocus=false,focusedIP=null){
    const query=filter.value.trim().toLowerCase().replaceAll("[.]",".");table.replaceChildren();
    const body=addHeading(table,["Source","Country","7d alerts","MISP"],["","","num","catalog-column"]);
    let shown=0;
    for(const [ip,n] of rows){
      const meta=d.enrich_meta?.[ip]||{},ctx=d.wazuh.source_context[ip]||{};
      const member=d.misp.top_source_membership[ip];
      if(!ip.includes(query)&&!String(meta.provider||meta.org||"").toLowerCase().includes(query))continue;
      const tr=row(body,["",meta.country||"—",metric(n),member===true?"Yes":member===false?"No":"Unknown"],["","","num","catalog-column"]);
      const button=add(tr.children[0],"button",defang(ip),"ip-action mono");button.type="button";
      button.setAttribute("aria-expanded","false");button.setAttribute("aria-controls","ioc-detail");byButton.set(button,ip);
      const open=(focus,scroll)=>{
        close();active={button,tr,ip};button.setAttribute("aria-expanded","true");root.hidden=false;empty.hidden=true;
        fillDetail(root,{ip,n,meta,member,ctx},()=>close(true));place();
        if(focus)root.focus?.({preventScroll:true});if(scroll)root.scrollIntoView?.({block:"nearest"});
      };
      button.addEventListener("click",()=>{if(active?.button===button)close(true);else open(true,true);});
      if(ip===keep)open(refocus,false);
      if(ip===focusedIP)button.focus?.({preventScroll:true});
      shown++;
    }
    if(!shown)add(add(body,"tr",""),"td",rows.length?"No sources match this filter.":"No displayed source rows. This does not imply zero alerts.","dim").colSpan=4;
    byId("source-scope").textContent=shown?`${shown} of ${rows.length} public source rows from the 7-day top-20 buckets.`:rows.length?"No sources match this filter.":"No displayed source rows; not zero alerts.";
  }
  filter.addEventListener("input",()=>{close();draw();});
  narrow?.addEventListener?.("change",()=>{if(active)place();});updateCoverage();draw();
  return (next,nextRows)=>{
    const ip=active?.ip, focused=document.activeElement;
    const refocus=focused===root||root.contains?.(focused);
    const focusedIP=byButton.get(focused);
    close();d=next;rows=nextRows;updateCoverage();draw(ip,refocus,focusedIP);
    if(ip&&!active)empty.textContent="The previously selected source is not in this batch's displayed rows.";
    if((ip&&!active&&refocus)||(focusedIP&&!table.contains?.(document.activeElement)))filter.focus?.({preventScroll:true});
  };
}
function renderDetails(d){
  for(const id of ["misp","runs","feeds"])byId(id).replaceChildren();
  const m=addHeading(byId("misp"),["Source","Updated (UTC)"]);
  const recent=Array.isArray(d.misp?.recent_14d)?d.misp.recent_14d:[];
  for(const item of recent.slice(0,12))if(validIP(item.ip))row(m,[defang(item.ip),item.date||"unknown"],["mono"]);
  if(!m.children.length) row(m,["—","No preview available"]);
  const r=addHeading(byId("runs"),["Completed (UTC)","Result"]);
  for(const run of (Array.isArray(d.runs)?d.runs:[]).slice(-8).reverse())row(r,[run.ts?.replace("T"," ").replace("Z","")||"unknown",run.status==="ok"?"OK":"CHECK"],["",run.status==="ok"?"ok":"bad"]);
  if(!r.children.length)row(r,["—","No prior runs available"]);
  const feeds=byId("feeds");add(feeds,"p","Review-only watchlist: verify locally before any response.","dim");
  add(feeds,"a","Published watchlist").href="blocklist.txt";
  byId("srcs").textContent="GreyNoise, OTX and AbuseIPDB provide context; Clear NDR and asset evidence stay private.";
}
function reveal(){
  const hash=globalThis.location?.hash?.slice(1);
  if(["changes","recent","method","integrations"].includes(hash)){
    byId(hash)?.closest?.("details")?.setAttribute("open","");byId(hash)?.scrollIntoView?.();
  }
}
function main(){
  let updateSources=null, diffReady=false;
  const refresh=publishedRefresh({accept:d=>Array.isArray(d?.wazuh?.top_src)&&d.wazuh.top_src.length<=20&&
    Boolean(d.misp?.top_source_membership&&d.wazuh?.source_context),paint:async({data:d,report,changed,complete})=>{
    if(!d){
      byId("gen").textContent="Snapshot unavailable";byId("status-pill").textContent="UNAVAILABLE";byId("status-pill").className="pill bad";
      byId("snapshot-note").textContent="Public snapshot unavailable. No counts or source conclusions can be drawn.";
      byId("snapshot-note").className="readout warn";return;
    }
    const model=PublicView.status(d.generated,report,Date.now(),complete),pill=byId("status-pill"),note=byId("snapshot-note");
    byId("gen").textContent=model.batchText;byId("agents").textContent=model.latest;
    pill.textContent=model.pill;pill.className=model.pill==="LAST RUN OK"?"pill":"pill bad";
    const revision=d.public_revision?.kind==="projection_correction"?` Display correction ${d.public_revision.corrected_utc}; not a new run.`:"";
    if(note.textContent!==model.note+revision)note.textContent=model.note+revision;
    note.className=model.pill==="LAST RUN OK"?"readout":"readout warn";
    if(changed){
      const rows=d.wazuh.top_src.filter(x=>Array.isArray(x)&&x.length===2&&validIP(x[0]));
      renderCards(d,rows);renderDaily(d);renderRanking(rows,d.enrich_meta);renderDetails(d);
      if(updateSources)updateSources(d,rows);
      else {updateSources=renderSources(d,rows);reveal();}
      diffReady=false;
    }
    if(!diffReady&&typeof renderSnapshotDiff==="function")diffReady=await renderSnapshotDiff(byId("changes"),d);
  }});
  globalThis.addEventListener?.("hashchange",reveal);return refresh.start();
}
main();
