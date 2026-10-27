"use strict";
// GitHub Pages is an allowlisted public summary, never a private case workspace.
const byId = id => document.getElementById(id);
const add = (parent, tag, text, className="") => {
  const element = document.createElement(tag);
  element.textContent = String(text);
  if (className) element.className = className;
  parent.appendChild(element);
  return element;
};
const number = value => Number.isFinite(Number(value)) ? Number(value) : 0;
const defang = ip => {const i=ip.lastIndexOf("."); return i<0 ? ip : ip.slice(0,i)+"[.]"+ip.slice(i+1);};
const validIP = ip => typeof ip==="string" && /^(?:\d{1,3}\.){3}\d{1,3}$/.test(ip)
  && ip.split(".").every(o=>Number(o)<=255);
const snapshotAgeHours = (stamp, now=Date.now()) => {
  const parsed=Date.parse(String(stamp||"").replace(" UTC","Z").replace(" ","T"));
  return Number.isFinite(parsed) && parsed<=now+600000 ? Math.max(0,(now-parsed)/3600000) : Infinity;
};
const sourceState = (meta, name) => meta?.sources?.[name]?.state || "unknown_age";
const stateLabel = state => ({fresh:"fresh",cached:"cached; latest attempt failed",stale:"stale (>48h)",
  not_observed:"not observed in lookup",unknown_age:"lookup age unknown",not_queried:"not queried"})[state] || "unknown";
const context = (meta, field, source) => {
  if (meta?.[field]===undefined || meta[field]===null || meta[field]==="") return `${source}: no result`;
  return `${source}: ${meta[field]} (${stateLabel(sourceState(meta, source))})`;
};
let sourceRows=[], snapshot=null;

function addRow(table, values, classes=[]) {
  const row=add(table,"tr","");
  values.forEach((value,index)=>add(row,"td",value,classes[index]||""));
  return row;
}
function addHeading(table, headings){
  const head=add(table,"thead","");const row=add(head,"tr","");
  headings.forEach(text=>{const cell=add(row,"th",text);cell.setAttribute("scope","col");});
  return add(table,"tbody","");
}
function renderCards(d){
  const cards=byId("kpis"); cards.replaceChildren();
  const items=[
    ["Wazuh alerts · 7d",number(d.wazuh?.total_7d).toLocaleString(),"Exact query total; batch snapshot"],
    ["MISP 1932 attributes",number(d.misp?.total).toLocaleString(),"Legacy ip-dst and new ip-src; not incidents"],
    ["VT comments logged",number(d.vt?.posted_total).toLocaleString(),"Cumulative local ledger; not recent activity or a verdict"],
    ["Public watchlist",number(d.blocklist_n).toLocaleString(),"Strict SSH + corroboration + IDS flag; review before action"],
  ];
  for (const [name,value,explain] of items) {
    const card=add(cards,"div","","card");add(card,"h2",name);add(card,"div",value,"big");add(card,"div",explain,"ksub");
  }
  byId("selection-explain").textContent=`${number(d.misp?.total).toLocaleString()} MISP IP attributes → `+
    `${number(d.blocklist_n).toLocaleString()} in the stricter public list: IDS-enabled, corroborated SSH source, `+
    `independent signal and non-cloud global IPv4. Older IDS flags are not proof of analyst review; `+
    `new automated entries start IDS-disabled. Never use this list as an automatic block decision.`;
}
function renderDaily(d){
  const days=Array.isArray(d.wazuh?.by_day)?d.wazuh.by_day:[];
  const root=byId("days");root.replaceChildren();
  const values=byId("day-values");values.replaceChildren();
  const max=Math.max(1,...days.map(x=>number(x[1])));
  for(const [day,count] of days){
    const bar=add(root,"div","","bar");bar.style.height=`${Math.max(3,Math.round(78*number(count)/max))}%`;
    bar.title=`${String(day)}: ${number(count).toLocaleString()} alerts`;
    add(bar,"span",String(day).slice(5));
    add(values,"span",`${String(day)}: ${number(count).toLocaleString()}`,"day-value");
  }
  byId("agent-privacy").textContent="Per-agent totals and host identities are private. Data shown is a 7-day batch, not live detection.";
}
function renderDetail(ip,count,meta,membership,sourceContext){
  const root=byId("ioc-detail");root.hidden=false;root.replaceChildren();
  add(root,"h2",`Source ${defang(ip)} · evidence limits`);
  add(root,"p",`${number(count).toLocaleString()} Wazuh alerts over 7 days. A source IP and alert volume alone do not prove attack success.`);
  add(root,"p",`Latest sampled alert: ${sourceContext?.last_sample_utc||"not available"} · ${sourceContext?.sample_behavior||"No alert sample available"}. At most three recent alerts were sampled; this is not a complete or dominant behavior timeline.`);
  const memberText=membership===true?"Present in full MISP Event 1932 (catalog, not incident evidence)":
    membership===false?"Not present in full MISP Event 1932 snapshot":"Full MISP membership unavailable";
  add(root,"p",memberText);
  const list=add(root,"ul","");
  const items=[["GreyNoise",meta?.gn,"gn"],["AbuseIPDB",meta?.aip,"aipdb"],["OTX pulses",meta?.otx,"otx"]];
  for(const [label,value,key] of items){
    const status=meta?.sources?.[key]||{};
    const present=value!==undefined && value!==null && value!=="";
    const line=`${label}: ${present?value:"no result"} · ${stateLabel(status.state||"not_queried")}`+
      (status.checked_at?` · checked ${status.checked_at}`:"");
    add(list,"li",line);
  }
  add(root,"p","This public view has no victim IPs, asset links, NDR evidence, successful-auth outcomes, or analyst case decisions. Confirm locally before responding.","dim");
  const next={"SSH authentication alert":"Look for this source in your own authentication telemetry; distinguish rejected attempts from verified successful access.",
    "Web request alert (outcome unverified)":"Review request sequence and response outcomes locally; HTTP errors alone do not show exploitation.",
    "Other detection (sample only)":"Inspect the original alert, affected asset and subsequent auth/process outcomes locally."};
  add(root,"p","Next local check: "+(next[sourceContext?.sample_behavior]||"Locate the original alert and verify its outcome locally."));
  const refs=add(root,"div","Public lookups: ","refs");
  for(const [label,prefix] of [["VT","https://www.virustotal.com/gui/ip-address/"],
    ["AbuseIPDB","https://www.abuseipdb.com/check/"],["GreyNoise","https://viz.greynoise.io/ip/"]]){
    const link=add(refs,"a",label);link.href=prefix+ip;link.target="_blank";link.rel="noopener noreferrer";
  }
}
function renderSources(d){
  const table=byId("src");const rows=Array.isArray(d.wazuh?.top_src)?d.wazuh.top_src:[];
  sourceRows=rows.filter(x=>Array.isArray(x)&&validIP(x[0]));
  const memberMap=d.misp?.top_source_membership||{};
  const metaMap=d.enrich_meta||{};
  const contextMap=d.wazuh?.source_context||{};
  const intake=d.wazuh?.pipeline_24h_coverage||{};
  const cap=number(intake.bucket_limit)||500;
  byId("pipeline-coverage").textContent=intake.outside_top_alerts===null||intake.outside_top_alerts===undefined
    ?`Separate 24h pipeline: top ${cap} source buckets; truncation not yet measured. This table is a separate 7d top-20 view.`
    :`Separate 24h pipeline: top ${cap} of approximately ${number(intake.approx_source_values)} source values; `+
      `${number(intake.outside_top_alerts)} alerts outside the top buckets · measured ${intake.measured_at_utc||"unknown UTC"}. `+
      `Estimate may include private IPs; this 7d table is not a complete source list.`;
  function draw(){
    const q=byId("source-filter").value.trim().toLowerCase();table.replaceChildren();
    const body=addHeading(table,["Source IP","Sampled behavior","Provider / org","Country","7d alerts","In 1932?","Enrichment coverage"]);
    let shown=0;
    for(const [ip,count] of sourceRows){
      const meta=metaMap[ip]||{};
      const ctx=contextMap[ip]||{};
      if(!ip.includes(q) && !String(meta.provider||meta.org||"").toLowerCase().includes(q))continue;
      const membership=Object.hasOwn(memberMap,ip)?memberMap[ip]:null;
      const presence=membership===true?"Yes":membership===false?"No":"Unknown";
      const coverage=[['GN','gn','gn'],['AIP','aipdb','aip'],['OTX','otx','otx']]
        .map(([label,key,val])=>`${label}: ${meta[val]===undefined?'—':stateLabel(sourceState(meta,key))}`).join(" · ");
      const row=addRow(body,[defang(ip),ctx.sample_behavior||"No sample",meta.provider||meta.org||"Not provided",meta.country||"—",
        number(count).toLocaleString(),presence,coverage],["mono","wrap","wrap","","num","","wrap"]);
      const cell=row.children[0];cell.replaceChildren();
      const button=add(cell,"button",defang(ip),"ip-action mono");button.type="button";
      button.setAttribute("aria-label",`Inspect source ${ip}`);
      button.addEventListener("click",()=>renderDetail(ip,count,meta,membership,ctx));
      shown++;
    }
    byId("source-scope").textContent=`${shown} of ${sourceRows.length} top global IPv4 sources · sampled behavior is not a verdict · full Event 1932 membership checked`;
  }
  byId("source-filter").addEventListener("input",draw);
  draw();
}
function renderMisp(d){
  const table=byId("misp");table.replaceChildren();const body=addHeading(table,["Observed source","Attribute updated (UTC)","Context"]);
  const recent=Array.isArray(d.misp?.recent_14d)?d.misp.recent_14d:[];
  for(const x of recent.slice(0,12))if(validIP(x.ip))addRow(body,[defang(x.ip),x.date||"unknown","Catalog entry; investigate locally"],["mono","","wrap"]);
  if(!recent.length)addRow(body,["—","—","No recent-attribute preview available"]);
}
function renderRuns(d){
  const table=byId("runs");table.replaceChildren();const body=addHeading(table,["Completed (UTC)","Status","Details"]);
  const runs=Array.isArray(d.runs)?d.runs:[];
  for(const run of runs.slice(-12).reverse()){
    const status=run.status==="ok"?"OK":"CHECK";
    addRow(body,[String(run.ts||"unknown").replace("T"," ").replace("Z",""),status,
      status==="OK"?"Completed":"Operational details withheld"],["",status==="OK"?"ok":"bad","wrap"]);
  }
}
function renderFeeds(){
  const root=byId("feeds");root.replaceChildren();
  function feed(name,description,linkText,href){
    const box=add(root,"div","","feed");add(box,"h3",name);const para=add(box,"p",description);
    if(href){add(para,"br","");const link=add(para,"a",linkText);link.href=href;link.rel="noopener noreferrer";link.target="_blank";}
  }
  feed("Review-only IP list","Only IDS-enabled MISP sources with corroborated SSH evidence; not the full catalog or a blocking directive.","Public watchlist", "blocklist.txt");
  feed("MISP exports","New automated attributes need analyst review before IDS use; legacy IDS flags are not automatically re-reviewed. Exports require authorization.","",null);
  feed("VirusTotal","A capped job shares selected, evidence-backed source observations. VT labels are not proof of compromise.","",null);
  feed("Private investigations","NDR alert samples, asset identities and incident decisions are not published on this page.","",null);
  const sources=byId("srcs");sources.replaceChildren();
  for(const [name,description] of [["GreyNoise","scanner context"],["OTX","pulse correlation"],
      ["AbuseIPDB","report score"],["Wazuh","local detections"],["Clear NDR","private alerts"]]){
    const box=add(sources,"div","","src");add(box,"b",name);add(box,"span"," — "+description);
  }
}
async function main(){
  try{
    const response=await fetch("data.json",{cache:"no-store"});if(!response.ok)throw Error(`HTTP ${response.status}`);
    const d=await response.json();if(!Array.isArray(d.wazuh?.top_src) || !d.misp?.top_source_membership || !d.wazuh?.source_context)
      throw Error("public snapshot incomplete; membership not verified");
    let report=null;
    try{const statusResponse=await fetch("status.json",{cache:"no-store"});
      if(statusResponse.ok)report=await statusResponse.json();}catch(_){/* Status remains unknown. */}
    snapshot=d;
    const age=snapshotAgeHours(d.generated);
    byId("gen").textContent="Generated "+String(d.generated||"unknown UTC")+
      (Number.isFinite(age)?` · snapshot about ${Math.floor(age)}h old`:" · age unknown");
    const reportAge=snapshotAgeHours(report?.last_attempt_utc);
    const validReport=report?.schema_version===1 && ["ok","degraded"].includes(report?.state) && reportAge<=24;
    byId("agents").textContent="Asset-level evidence: private · last pipeline attempt "+
      (validReport?`${report.last_attempt_utc} (${report.state})`:"unknown");
    const pill=byId("status-pill");
    if(age>24){pill.textContent="STALE SNAPSHOT";pill.className="pill bad";}
    else if(!validReport){pill.textContent="STATUS UNKNOWN";pill.className="pill bad";}
    else if(report.state==="degraded"){pill.textContent="PIPELINE DEGRADED";pill.className="pill bad";}
    else pill.textContent="LAST RUN OK";
    renderCards(d);renderDaily(d);renderSources(d);renderMisp(d);renderRuns(d);renderFeeds();
  }catch(e){
    byId("gen").textContent="Public snapshot unavailable: "+e.message;
    byId("status-pill").textContent="UNAVAILABLE";byId("status-pill").className="pill bad";
    // Don't imply zero alerts or incidents when the data fetch fails.
  }
}
main();
