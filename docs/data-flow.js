"use strict";
// Logical public relationships only. No endpoints, observed addresses, or secrets.
const DataFlow=(()=>{
  const layers=["Collection","Enrichment","Action"];
  // id, layer, title, short label, role, trust boundary
  const nodes=[
    ["indexer",0,"Wazuh Indexer","Alerts and source buckets","Reads recent source buckets and verifies individual SSH authentication-failure alerts locally. It also supplies the separate seven-day public projection.","Private telemetry. Raw alerts, target details and per-Agent data are never published."],
    ["manager",0,"Wazuh Manager","Agent inventory","Checks the completeness and state of the Agent inventory. A required offline or missing Agent prevents external sharing.","Private inventory. This is health metadata, not additional alerts."],
    ["store",0,"Local threat DB","SQLite · private","Stores sampled observations and history locally. Basic intake can still run when the sharing preflight fails.","Not a bulk export source. The database and its evidence stay private."],
    ["logs",0,"Local log hunt","Host log review","A scheduled local log scan produces private evidence for an analyst. Findings do not automatically become public indicators.","Private host logs. No log text is sent to Pages or VT."],
    ["ndr",0,"Clear NDR","Network alerts","A scheduled status check and a bounded 24-hour network-alert query support cross-checking against Event 1932.","Private telemetry. The query is not an inventory of all network activity."],
    ["arkime",0,"Arkime","Sessions · on demand","An analyst can inspect a session on demand. This is not a timed full-session export or a proven join with Wazuh.","Private session evidence. No endpoints or session details leave the internal review workflow."],
    ["preflight",1,"Sharing preflight","Coverage and eligibility","Agent and Indexer health govern whether the orchestrator may do external lookups and write to MISP. It filters out protected or non-shareable addresses before lookup.","On a hard preflight failure, keep useful intake local and withhold external sharing."],
    ["grey",1,"GreyNoise","Bounded lookup","Adds scanner and reputation context. A 429 pauses GreyNoise independently for at least 24 hours locally.","External: receives eligible public source addresses, not alert messages or target data."],
    ["otx",1,"AlienVault OTX","Bounded lookup","Adds pulse context under a per-run quota. HTTP 429 pauses the provider locally; errors do not mean zero pulses.","External: receives eligible public source addresses only."],
    ["abuse",1,"AbuseIPDB","Bounded lookup","Adds abuse-report context. A score is not proof of an attack or a compromise.","External: receives eligible public source addresses only."],
    ["cache",1,"Enrichment cache","Lookup age and result","Successful or explicit not-found results can be reused for 24 hours without changing their observation time. Missing, failed, cached and limited lookups remain distinct.","Private cache. Only approved fields enter the public projection or comments."],
    ["cidrs",1,"MISP Warninglists","Local CIDR context","Matches public AWS, Azure, GCP and Cloudflare range lists locally. Matching a range does not change eligibility, certify a source, or make it an allowlist.","Only list downloads leave the system; no observed addresses are sent to those list publishers."],
    ["cross",1,"NDR × MISP","Scoped 24-hour cross-check","Uses the published attributes of Event 1932 for a bounded alert query. Missing or incomplete data is not a negative finding.","Raw matches stay private. No match is not evidence that the network is clean."],
    ["misp",2,"MISP Event 1932","Review-only catalog","New qualified source observations are written as ip-src with IDS disabled. The workflow confirms the published readback; ambiguity leaves an intent for reconciliation, not a replayed write.","Controlled catalog, not an incident database or authorization to block."],
    ["analyst",2,"Analyst review","Evidence and decisions","An operator can compare logs, network alerts and sessions and record the evidence, decision, expiry and revocation.","The private decision ledger does not automatically write to MISP or Pages."],
    ["release",2,"Release checks","Privacy and evidence","Required stages must complete for the full snapshot and VT workflow. Watchlist and VT decisions need verified same-source SSH failures and recent independent corroboration; watchlist entries also need an IDS flag.","A failed VT job can also hold the full snapshot. Backup failure degrades the run but may still allow a safe snapshot. Publication and internal writes are separate outcomes."],
    ["vt",2,"VirusTotal","Capped comments only","Posts only an eligible, deduplicated source comment: up to three per run and six per UTC day. The scheduled job does not vote.","External: reviewed source context only; never raw evidence. Zero posts may be the correct result."],
    ["pages",2,"GitHub Pages","Public snapshot and heartbeat","Publishes the approved aggregate snapshot, filtered source rows, watchlist and batch comparison. On required-stage failure it keeps the last safe batch and attempts a degraded heartbeat.","Public: snapshot not a live feed. No sensor locations, private matches or decisions."],
    ["telegram",2,"Telegram","Bounded notifications","Used for failures and selected notices. A sent request does not by itself prove delivery or receipt.","External notification channel, not an authoritative run ledger or a public evidence endpoint."],
    ["backup",2,"Local backup","Daily recovery archive","A separate 02:30 UTC job keeps a restricted recovery archive; the scheduled SOC job checks the daily archive. An archive check is not a complete restore test.","Private recovery files never enter GitHub Pages."],
  ];
  const edges=[
    ["manager","preflight","run","Agent health and inventory completeness"],
    ["indexer","preflight","run","Alert freshness, query integrity and source eligibility"],
    ["indexer","store","run","Bounded local observation intake"],
    ["indexer","cidrs","run","Private match against downloaded ranges"],
    ["preflight","grey","run","Eligible addresses under the provider budget"],
    ["preflight","otx","run","Eligible addresses under the provider budget"],
    ["preflight","abuse","run","Eligible addresses under the provider budget"],
    ["grey","cache","run","Result, age and lookup outcome"],
    ["otx","cache","run","Result, age and lookup outcome"],
    ["abuse","cache","run","Result, age and lookup outcome"],
    ["preflight","misp","run","Gated observation selection; default IDS off"],
    ["cache","misp","run","Selected context for catalog observations"],
    ["misp","cross","run","Read published source indicators"],
    ["ndr","cross","run","Verified alert results for the scoped query"],
    ["cross","analyst","review","Private corroborating context"],
    ["logs","analyst","review","Local log evidence"],
    ["arkime","analyst","review","On-demand session verification"],
    ["cidrs","analyst","review","Private network ownership context, not an exclusion"],
    ["misp","analyst","review","Inspect managed attributes or reconcile ambiguous writes"],
    ["misp","release","run","Required publication confirmation and catalog context"],
    ["cross","release","run","Required NDR cross-check completion"],
    ["ndr","release","run","Required NDR status check completion"],
    ["logs","release","run","Required local hunt completion"],
    ["indexer","release","run","Separate public aggregation and source-specific SSH proof"],
    ["cache","release","run","Fresh corroboration or explicitly bounded lookup state"],
    ["release","vt","run","Eligible comment only; withhold on failed prerequisites"],
    ["release","pages","run","Privacy-checked snapshot or heartbeat-only update"],
    ["release","telegram","run","Operational failure notice"],
    ["misp","telegram","run","Selected notice of newly confirmed observations"],
    ["cross","telegram","run","Selected notice of eligible matches; no raw network evidence"],
    ["store","backup","run","Private threat database recovery copy"],
    ["analyst","backup","run","Private decision ledger if present"],
  ];
  const byId=new Map(nodes.map(n=>[n[0],n]));
  function neighbors(id){return new Set(edges.filter(e=>e[0]===id||e[1]===id).flatMap(e=>e.slice(0,2)));}
  function heartbeat(doc,now){
    if(doc?.schema_version!==1||!['ok','degraded','unknown'].includes(doc.state))return "Published heartbeat unavailable. This is a logical graph.";
    const t=PublicView.utc(doc.last_attempt_utc);
    if(!Number.isFinite(t)||t>now+600000)return "Published heartbeat unavailable. This is a logical graph.";
    const overdue=t<PublicView.due(now)?" · schedule overdue":"";
    return `Last published attempt: ${doc.last_attempt_utc} · ${doc.state}${overdue}. Not per-service status.`;
  }
  return {layers,nodes,edges,byId,neighbors,heartbeat};
})();

function mountDataFlow(doc){
  const el=id=>doc.getElementById(id), svg=(tag,attrs)=>{
    const node=doc.createElementNS('http://www.w3.org/2000/svg',tag);
    for(const [k,v] of Object.entries(attrs))node.setAttribute(k,String(v));return node;
  };
  const add=(parent,tag,text,cls)=>{
    const node=doc.createElement(tag);node.textContent=text;if(cls)node.className=cls;parent.appendChild(node);return node;
  };
  const deck=el('graph-lanes'), stage=el('graph-stage'), detail=el('graph-detail'), dock=el('graph-dock');
  const narrow=globalThis.matchMedia?.('(max-width: 760px)');
  const buttons=new Map(), lanes=DataFlow.layers.map(title=>{
    const lane=add(deck,'section','','graph-lane');add(lane,'h2',title);return lane;
  });
  let selected='indexer', all=false;
  for(const [id,lane,title,short] of DataFlow.nodes){
    const button=add(lanes[lane],'button','','graph-node');button.type='button';button.id=`node-${id}`;
    button.setAttribute('aria-controls','graph-detail');
    add(button,'strong',title);add(button,'span',short);buttons.set(id,button);
    button.addEventListener('click',()=>select(id));
  }
  function moveDetail(){
    const button=buttons.get(selected);
    if(narrow?.matches){if(button.nextElementSibling!==detail)button.after(detail);}
    else if(detail.parentNode!==dock)dock.appendChild(detail);
  }
  function draw(){
    const wires=el('graph-wires'), layer=el('wire-layer');layer.replaceChildren();
    if(narrow?.matches)return;
    const box=stage.getBoundingClientRect();
    if(box.width<=0||box.height<=0)return;
    wires.setAttribute('viewBox',`0 0 ${box.width} ${box.height}`);
    const path=(e,idx)=>{
      const [s,t,kind]=e, active=s===selected||t===selected;
      if(!active&&!all)return;
      const a=buttons.get(s).getBoundingClientRect(),b=buttons.get(t).getBoundingClientRect();
      const same=DataFlow.byId.get(s)[1]===DataFlow.byId.get(t)[1], forward=a.left<b.left;
      const x=(forward?a.right:same?a.right:a.left)-box.left, end=(forward?b.left:same?b.right:b.right)-box.left;
      const y=a.top+a.height/2-box.top, ey=b.top+b.height/2-box.top;
      const dir=forward?1:-1, shift=Math.max(8,Math.min(28,Math.abs(end-x)*.45));
      const route=same?`M${x},${y} C${x+10+idx%4*3},${y} ${end+10+idx%4*3},${ey} ${end},${ey}`:
        `M${x},${y} C${x+dir*shift},${y} ${end-dir*shift},${ey} ${end},${ey}`;
      layer.appendChild(svg('path',{d:route,class:`graph-wire${active?' is-focused':''}${kind==='review'?' is-review':''}`,'marker-end':'url(#wire-tip)'}));
    };
    DataFlow.edges.forEach((e,i)=>{if(e[0]!==selected&&e[1]!==selected)path(e,i);});
    DataFlow.edges.forEach((e,i)=>{if(e[0]===selected||e[1]===selected)path(e,i);});
  }
  function inspect(){
    const [,layer,title,,note,boundary]=DataFlow.byId.get(selected);
    el('node-layer').textContent=DataFlow.layers[layer];el('node-title').textContent=title;
    el('node-note').textContent=note;el('node-boundary').textContent=boundary;
    const root=el('node-links');root.replaceChildren();
    for(const [heading,idx] of [['Receives from',1],['Sends or contributes to',0]]){
      const found=DataFlow.edges.filter(e=>e[idx]===selected);add(root,'h3',heading);
      if(!found.length){add(root,'p',idx===1?'No upstream component shown.':'No downstream component shown.','note');continue;}
      const list=add(root,'ul','','graph-link-list');
      for(const e of found){
        const other=e[1-idx], li=add(list,'li',''),button=add(li,'button',DataFlow.byId.get(other)[2]);button.type='button';
        button.addEventListener('click',()=>{select(other);buttons.get(other).focus();buttons.get(other).scrollIntoView({block:'nearest'});});
        add(li,'p',(e[2]==='review'?'On demand · ':'')+e[3],'note');
      }
    }
  }
  function select(id){
    selected=id;const linked=DataFlow.neighbors(id);
    for(const [key,b] of buttons){b.setAttribute('aria-pressed',String(key===id));b.classList.toggle('is-linked',key!==id&&linked.has(key));}
    detail.hidden=false;moveDetail();inspect();draw();
  }
  select(selected);
  const toggle=el('graph-all');toggle.addEventListener('click',()=>{
    all=!all;toggle.setAttribute('aria-pressed',String(all));toggle.textContent=all?'Show selected connections':'Show all connections';draw();
  });
  narrow?.addEventListener?.('change',()=>{moveDetail();draw();});
  if(typeof ResizeObserver==='function')new ResizeObserver(draw).observe(stage);else globalThis.addEventListener?.('resize',draw);
  const hb=el('graph-heartbeat');
  async function refresh(){
    let status=null;
    try{const r=await fetch('status.json',{cache:'no-store',signal:globalThis.AbortSignal?.timeout?.(12000)});if(r.ok)status=await r.json();}catch(_){/* No published evidence. */}
    const label=DataFlow.heartbeat(status,Date.now());if(hb.textContent!==label)hb.textContent=label;
  }
  refresh();globalThis.setInterval?.(()=>{if(!doc.hidden)refresh();},60000);
}
if(typeof document!=="undefined")mountDataFlow(document);
