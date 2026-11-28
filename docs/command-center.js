"use strict";
const byId=id=>document.getElementById(id);
const numberValue=v=>Number.isFinite(Number(v))?Number(v):null;
const format=n=>numberValue(n)===null?"N/A":Number(n).toLocaleString();
const compact=n=>{const v=numberValue(n);if(v===null)return"N/A";if(v>=1e9)return(v/1e9).toFixed(1)+"B";if(v>=1e6)return(v/1e6).toFixed(1)+"M";if(v>=1e3)return(v/1e3).toFixed(1)+"K";return v.toLocaleString();};
const percent=(v,d=1)=>numberValue(v)===null?"N/A":Number(v).toFixed(d)+"%";
const ratioPercent=(v,d=1)=>numberValue(v)===null?"N/A":(Number(v)*100).toFixed(d)+"%";
const statusClass=s=>s==="healthy"?"healthy":s==="attention"||s==="stale"?"attention":"";
const statusLabel=s=>s==="healthy"?"healthy":s==="attention"?"attention":s==="stale"?"stale":"pending";
function add(parent,tag,text,css=""){const el=document.createElement(tag);el.textContent=String(text);if(css)el.className=css;parent.appendChild(el);return el;}
function setBadge(id,status){const el=byId(id);el.textContent=statusLabel(status);el.className="cc-badge "+statusClass(status);}
function setMeter(id,value,max){const el=byId(id);el.max=max;el.value=Math.max(0,Math.min(max,numberValue(value)||0));}
function metrics(id,items){const root=byId(id);root.replaceChildren();for(const [label,value] of items){const card=add(root,"div","","cc-metric");add(card,"span",label);add(card,"strong",value);}}
function kpis(d){
 const root=byId("kpis");root.replaceChildren();
 const cards=[
  ["Nodes ready",`${format(d.cluster.nodes_ready)} / ${format(d.cluster.nodes_total)}`,"K3s control-plane and etcd voters"],
  ["Indexed security docs",compact(d.security_logs.indexed_documents),"OpenSearch aggregate"],
  ["Security alerts",compact(d.security_logs.alert_documents),"Includes informational noise"],
  ["RAG events",compact(d.rag.events),"Evidence and case corpus"],
  ["AI audit requests",compact(d.ai.audit_requests),"Gateway request records"],
  ["Unique asset IPs",compact(d.asset_intel.unique_ips),"Historical Internet asset intelligence"]
 ];
 for(const [title,value,note] of cards){const card=add(root,"div","","cc-kpi");add(card,"h2",title);add(card,"strong",value);add(card,"p",note);}
}
function renderCluster(d){
 const c=d.cluster;setBadge("cluster-status",c.status);
 metrics("cluster-metrics",[
  ["etcd voters",format(c.etcd_voters)],
  ["allocatable CPU",format(c.allocatable_cpu_cores)+" cores"],
  ["allocatable memory",format(c.allocatable_memory_gib)+" GiB"],
  ["K3s version",c.version],
  ["latest snapshot",c.latest_snapshot_utc||"N/A"],
  ["retained warning events",format(c.retained_warning_events)]
 ]);
 byId("cluster-nodes-label").textContent=`${format(c.nodes_ready)} / ${format(c.nodes_total)}`;
 byId("cluster-pods-label").textContent=`${format(c.pods_ready)} / ${format(c.pods_total)}`;
 setMeter("cluster-nodes-meter",c.nodes_ready,Math.max(1,c.nodes_total));
 setMeter("cluster-pods-meter",c.pods_ready,Math.max(1,c.pods_total));
}
function renderSecurity(d){
 const s=d.security_logs;setBadge("security-status",s.status);
 metrics("security-metrics",[
  ["alert documents",compact(s.alert_documents)],
  ["anomaly documents",compact(s.anomaly_documents)],
  ["Arkime sessions",compact(s.arkime_sessions)],
  ["coverage gap",format(s.coverage_gap_days)+" days"],
  ["Arkime capture",s.arkime_capture_active?"active":"inactive"],
  ["top signature share",percent(s.top_signature_share_pct,2)]
 ]);
 byId("security-noise-label").textContent=percent(s.top_signature_share_pct,2);
 setMeter("security-noise-meter",s.top_signature_share_pct,100);
 byId("security-note").textContent=s.arkime_capture_active?"Capture is active; verify freshness and completeness independently.":"Capture is inactive. Historical session data remains available, but recent packet-level correlation is incomplete.";
}
function renderRag(d){
 const r=d.rag;setBadge("rag-status",r.status);
 const active=r.case_status?.active??0;
 metrics("rag-metrics",[
  ["events",compact(r.events)],
  ["cases",compact(r.cases)],
  ["active cases",format(active)],
  ["assets",format(r.assets)],
  ["human feedback",format(r.feedback)],
  ["triage coverage",percent(r.triaged_pct,2)],
  ["unresolved DLQ",format(r.dlq_unresolved)],
  ["case backlog",format(r.case_backlog)]
 ]);
 byId("rag-embedding-label").textContent=percent(r.embedding_coverage_pct,2);
 byId("rag-recall-label").textContent=ratioPercent(r.recall_at5,1);
 setMeter("rag-embedding-meter",r.embedding_coverage_pct,100);
 setMeter("rag-recall-meter",r.recall_at5,1);
 byId("rag-note").textContent=`Recall@5 ${ratioPercent(r.recall_at5,1)} · Top-5 duplicate rate ${ratioPercent(r.duplicates_at5,1)}. Retrieval quality and pipeline reliability are separate gates.`;
}
function renderAi(d){
 const a=d.ai,s=d.agent_sessions;setBadge("ai-status",a.status);
 metrics("ai-metrics",[
  ["audit requests",compact(a.audit_requests)],
  ["success rate",percent(a.success_rate_pct,2)],
  ["gateway errors",format(a.gateway_error_requests)],
  ["gateway error rate",percent(a.gateway_error_rate_pct,2)],
  ["agent sessions",format(s.sessions)],
  ["stored messages",compact(s.messages)],
  ["input tokens",compact(s.input_tokens)],
  ["recorded cost",Number(s.recorded_cost||0).toFixed(2)]
 ]);
 byId("ai-success-label").textContent=percent(a.success_rate_pct,2);
 setMeter("ai-success-meter",a.success_rate_pct,100);
 byId("ai-note").textContent="Recorded cost is partial: some agents and providers do not report token or cost fields consistently.";
}
function renderAssets(d){
 const a=d.asset_intel;setBadge("assets-status",a.status);
 metrics("asset-metrics",[
  ["host records",compact(a.host_records)],
  ["unique IPs",compact(a.unique_ips)],
  ["data age",format(a.stale_days)+" days"],
  ["decision status",a.status]
 ]);
 byId("asset-note").textContent=a.status==="stale"?"Asset intelligence is historical. Refresh before using it for current exposure or active-validation decisions.":"Asset intelligence is within the configured freshness window.";
}
function renderGates(d){
 const root=byId("quality-gates");root.replaceChildren();
 const gates=[
  ["Kubernetes",d.cluster.status,`${format(d.cluster.nodes_ready)}/${format(d.cluster.nodes_total)} nodes · ${format(d.cluster.pods_ready)}/${format(d.cluster.pods_total)} Pods`],
  ["Security log coverage",d.security_logs.status,`${format(d.security_logs.coverage_gap_days)}-day gap · capture ${d.security_logs.arkime_capture_active?"active":"inactive"}`],
  ["Security RAG",d.rag.status,`${format(d.rag.dlq_unresolved)} unresolved DLQ · ${format(d.rag.case_backlog)} case backlog`],
  ["AI Gateway",d.ai.status,`${percent(d.ai.success_rate_pct,2)} audit success`],
  ["Asset intelligence",d.asset_intel.status,`${format(d.asset_intel.stale_days)} days old`]
 ];
 for(const [name,status,detail] of gates){const li=add(root,"li","");const left=add(li,"span","");add(left,"strong",name+" · ");add(left,"span",detail,"minor");add(li,"span",statusLabel(status),"cc-gate-state "+statusClass(status));}
}
function render(d){
 if(!d||d.schema_version!==1||d.public_safe!==true)throw new Error("Unexpected dashboard schema");
 byId("generated").textContent="Generated "+d.generated_utc;
 kpis(d);renderCluster(d);renderSecurity(d);renderRag(d);renderAi(d);renderAssets(d);renderGates(d);
 const states=[d.cluster.status,d.security_logs.status,d.rag.status,d.ai.status,d.asset_intel.status];
 const overall=states.every(x=>x==="healthy")?"healthy":"attention";
 setBadge("overall-status",overall);
 const attention=states.filter(x=>x!=="healthy").length;
 byId("snapshot-note").textContent=overall==="healthy"?"All published aggregate gates are healthy. This does not prove complete coverage or absence of compromise.":`Cluster is ${d.cluster.status}; ${attention} data domain${attention===1?"":"s"} need attention. Review the quality gates below.`;
}
async function load(){
 const button=byId("refresh-now");button.disabled=true;byId("refresh-status").textContent="Checking published aggregate JSON…";
 try{
  const response=await fetch("command-center-data.json?ts="+Date.now(),{cache:"no-store"});
  if(!response.ok)throw new Error(`HTTP ${response.status}`);
  render(await response.json());byId("refresh-status").textContent="Published snapshot checked; static data, not live telemetry.";
 }catch(error){
  byId("overall-status").textContent="unavailable";byId("overall-status").className="cc-badge attention";
  byId("snapshot-note").textContent="Aggregate snapshot unavailable. Do not infer healthy or zero activity.";
  byId("refresh-status").textContent="Refresh failed: "+error.message;
 }finally{button.disabled=false;}
}
byId("refresh-now").addEventListener("click",load);
load();setInterval(load,300000);
