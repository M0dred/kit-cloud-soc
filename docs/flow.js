"use strict";
// Public country projection: join internally by the already published source key; render aggregates only.
(() => {
  const get = id => document.getElementById(id);
  const n = value => Number.isSafeInteger(value) && value>=0;
  const fmt = value => n(value)?value.toLocaleString():"N/A";
  const pct = (value,total) => total>0?`${(100*value/total).toFixed(1)}%`:"N/A";
  const codes = new Set("AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW".split(" "));
  const naming = typeof Intl.DisplayNames==="function"?new Intl.DisplayNames(["en"],{type:"region",fallback:"code"}):null;
  const name = code => code==="unknown"?"Unknown country":(naming?.of(code)||code);
  // Reporting rollup only; never write back into the snapshot or outline.
  const chinaLabels = Object.freeze(["CN","TW","HK"]);
  const labels = ["SSH authentication alert","Web request alert (outcome unverified)","Other detection (sample only)","No sample label available"];
  const providers = [["gn","GreyNoise"],["otx","OTX"],["aipdb","AbuseIPDB"]];
  const keys = ["fresh","cached / stale","error / limited","other / unknown"];
  const own = (obj, key) => obj && Object.hasOwn(obj,key)?obj[key]:undefined;
  const ipKey = key => typeof key==="string" && /^(?:\d{1,3}\.){3}\d{1,3}$/.test(key) && key.split(".").every(part=>Number(part)<=255 && String(Number(part))===part);
  const add = (parent,tag,text) => {const el=document.createElement(tag);el.textContent=text;parent.appendChild(el);return el;};
  const svg = (parent,tag,attrs,text) => {
    const el=document.createElementNS("http://www.w3.org/2000/svg",tag);
    for (const [key,val] of Object.entries(attrs)) el.setAttribute(key,String(val));
    if (text!==undefined) el.textContent=text;
    parent.appendChild(el);return el;
  };
  function utc(stamp) {
    if (typeof stamp!=="string" || !/^\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC$/.test(stamp)) return NaN;
    const ms=Date.parse(stamp.replace(" ","T").replace(" UTC","Z"));
    return Number.isFinite(ms) && new Date(ms).toISOString().slice(0,16).replace("T"," ")+" UTC"===stamp?ms:NaN;
  }
  function lookup(status) {
    if (["error","rate_limited"].includes(status?.last_attempt) || ["rate_limited","lookup_failed"].includes(status?.state)) return 2;
    if (status?.state==="fresh") return 0;
    if (["cached","stale"].includes(status?.state)) return 1;
    return 3;
  }
  function aggregate(snapshot, combineChina) {
    const rows=snapshot.wazuh?.top_src;
    if (!Array.isArray(rows) || rows.length>20) throw Error("invalid public rows");
    const groups=new Map(), seen=new Set();
    let subset=0, labelled=0;
    for (const row of rows) {
      if (!Array.isArray(row) || row.length!==2 || !ipKey(row[0]) || seen.has(row[0]) || !n(row[1])) throw Error("invalid source bucket");
      const [ip,alerts]=row;
      seen.add(ip);
      const meta=own(snapshot.enrich_meta,ip);
      const original=codes.has(meta?.country)?meta.country:"unknown";
      const code=combineChina && chinaLabels.includes(original)?"CN":original;
      if (original!=="unknown") labelled+=1;
      if (!groups.has(code)) groups.set(code,{code,alerts:0,rows:0,membership:[0,0,0],samples:[0,0,0,0],
        lookups:providers.map(()=>[0,0,0,0]),origins:new Map(),members:combineChina && code==="CN"?chinaLabels:[code]});
      const g=groups.get(code);
      const part=g.origins.get(original)||{alerts:0,rows:0};
      part.alerts+=alerts;part.rows+=1;g.origins.set(original,part);
      g.alerts+=alerts; subset+=alerts; g.rows+=1;
      if (!n(subset)) throw Error("unsafe aggregate count");
      const member=own(snapshot.misp?.top_source_membership,ip);
      g.membership[member===true?0:member===false?1:2]+=1;
      const sample=labels.indexOf(own(snapshot.wazuh?.source_context,ip)?.sample_behavior);
      g.samples[sample>=0?sample:3]+=1;
      providers.forEach(([k],i)=>{g.lookups[i][lookup(own(meta?.sources,k))]+=1;});
    }
    return {groups,subset,labelled,rows:rows.length};
  }
  function heartbeat(report,batch,now) {
    const attempt=utc(report?.last_attempt_utc);
    if (report?.schema_version!==1 || !["ok","degraded","unknown"].includes(report.state) || !Number.isFinite(attempt) || attempt>now+600000) return "Pipeline heartbeat unavailable. This is a batch, not a live view.";
    const head=`Last reported attempt: ${report.last_attempt_utc} · ${report.state}.`;
    if (attempt<batch-15*60000) return `${head} This heartbeat does not verify the displayed batch.`;
    if (now-attempt>86400000) return `${head} Heartbeat is over 24 hours old.`;
    if (attempt>batch+15*60000 || report.state==="degraded") return `${head} The chart shows the last published data batch, not a fresh run.`;
    return head;
  }
  function drawDepth(list,metric) {
    const range=(id,low,high,fallback)=>Math.min(high,Math.max(low,Number(get(id).value)||fallback));
    const yaw=range("country-angle",-30,30,0), tilt=range("country-tilt",12,32,22);
    get("country-angle-value").textContent=`${yaw}°`;get("country-tilt-value").textContent=`${tilt}°`;
    const a=yaw*Math.PI/180,b=tilt*Math.PI/180;
    const view=([x,y,z])=>[360+x*Math.cos(a)+z*Math.sin(a),194-y*Math.cos(b)+(z*Math.cos(a)-x*Math.sin(a))*Math.sin(b)].map(v=>Math.round(v*10)/10);
    const point=xyz=>view(xyz).join(",");
    const grid=get("country-guides"), layer=get("country-shapes");
    grid.replaceChildren();layer.replaceChildren();
    if (!list.length) return;
    const max=list[0][metric], height=k=>max?126*k/max:0;
    const levels=max>1?[0,Math.floor(max/2),max]:max===1?[0,1]:[0];
    for (const value of levels) {
      const y=height(value), [x,sy]=view([-267,y,-24]);
      svg(grid,"polyline",{points:`${point([-258,y,-24])} ${point([258,y,-24])}`,class:"rank-guide"});
      svg(grid,"text",{x,y:sy+4,class:"rank-tick"},fmt(value));
    }
    const spacing=Math.min(120,500/list.length);
    const layout=list.map((g,i)=>({g,x:(i-(list.length-1)/2)*spacing}));
    const order=yaw>=0?[...layout].reverse():layout;
    for (const {g,x} of order) {
      const t=height(g[metric]), l=x-spacing*.23,r=x+spacing*.23;
      const face=(p,role)=>svg(layer,"polygon",{points:p.map(point).join(" "),class:`rank-face ${role}${g.code==="unknown"?" rank-unknown":""}`});
      if (t>0) {
        const side=yaw>=0?l:r;
        face([[side,0,-19],[side,0,19],[side,t,19],[side,t,-19]],"rank-side");
        face([[l,0,19],[r,0,19],[r,t,19],[l,t,19]],"");
      }
      face([[l,t,-19],[r,t,-19],[r,t,19],[l,t,19]],"rank-top");
    }
    for (const {g,x} of layout) {
      const [px,py]=view([x,0,35]);
      svg(layer,"text",{x:px,y:py+18,class:"rank-label"},g.code==="unknown"?"Unknown":g.code);
    }
  }
  function render(snapshot,report) {
    const now=Date.now(), batch=utc(snapshot?.generated);
    if (!Number.isFinite(batch) || batch>now+600000) throw Error("invalid batch time");
    const grouping=get("country-grouping");
    let {groups,subset,labelled,rows}=aggregate(snapshot,grouping.value!=="separate");
    get("country-batch").textContent=`Published batch: ${snapshot.generated}.${now-batch>86400000?" Snapshot is over 24 hours old.":""}`;
    get("country-heartbeat").textContent=heartbeat(report,batch,now);
    get("total-alerts").textContent=fmt(snapshot.wazuh.total_7d);
    get("selected-alerts").textContent=fmt(subset);
    get("labelled-rows").textContent=`${fmt(labelled)} / ${fmt(rows)}`;
    const sort=get("measure"), toggle=get("toggle-depth"), chart=get("chart-depth");
    let selected=null, visible=[], metric="alerts";
    const buttons=new Map();
    const map=typeof createCountryMap==="function"?createCountryMap(code=>{selected=code;detail();}):null;
    if (!map) get("map-status").textContent="Pulse map unavailable. Rankings and table are still available.";
    function detail() {
      const root=get("country-detail"), g=groups.get(selected);
      root.replaceChildren();
      if (!g) {add(root,"p","No source buckets to break down; this does not mean no alerts.");return;}
      add(root,"h2",name(g.code));
      add(root,"p",`${fmt(g.alerts)} alerts in the displayed buckets · ${pct(g.alerts,subset)} of this subset · ${fmt(g.rows)} source rows.`);
      if (g.members.length>1) {
        add(root,"h3","Original label breakdown · published subset");
        const origins=add(root,"ul","");
        for (const code of g.members) {
          const part=g.origins.get(code);
          add(origins,"li",`${name(code)} (${code}): ${part?`${fmt(part.rows)} source rows · ${fmt(part.alerts)} bucket alerts`:"No published source rows in this batch"}.`);
        }
      }
      add(root,"h3","MISP catalog membership · source rows");
      add(root,"p",`Present: ${fmt(g.membership[0])} · Absent: ${fmt(g.membership[1])} · Unknown: ${fmt(g.membership[2])}.`);
      add(root,"h3","Sample labels · source rows, not event counts");
      const samples=add(root,"ul","");
      for (const [i,label] of labels.entries()) add(samples,"li",`${label}: ${fmt(g.samples[i])}`);
      add(root,"h3","Provider coverage · source rows");
      const table=add(root,"table","");table.className="lookup-table";table.setAttribute("aria-label","Lookup coverage by provider");
      const titles=add(add(table,"thead",""),"tr","");
      for (const label of ["Provider",...keys]) add(titles,"th",label).setAttribute("scope","col");
      const body=add(table,"tbody","");
      providers.forEach(([,label],i)=>{
        const tr=add(body,"tr","");add(tr,"th",label).setAttribute("scope","row");
        for (const k of g.lookups[i]) add(tr,"td",fmt(k));
      });
      const note=add(root,"p","Lookup freshness is per provider; it does not date or verify a country label.");note.className="note";
      for (const [code,button] of buttons) button.setAttribute("aria-pressed",String(code===selected));
    }
    function rerank() {
      metric=sort.value==="rows"?"rows":"alerts";
      const sorted=[...groups.values()].sort((a,b)=>b[metric]-a[metric] || a.code.localeCompare(b.code));
      if (!groups.has(selected)) selected=sorted[0]?.code;
      visible=sorted.slice(0,8);
      const bars=get("country-bars"), body=get("country-rows");bars.replaceChildren();body.replaceChildren();buttons.clear();
      get("region-scope").textContent=sorted.length?`Ranked by ${metric==="rows"?"published source rows":"reported bucket alert counts"}. Chart: ${visible.length} of ${sorted.length} groups; table: all groups.`:"No public source buckets were available in this batch.";
      bars.setAttribute("aria-label",metric==="rows"?"Country source row count":"Country bucket alert count");
      for (const g of visible) {
        const row=add(bars,"li","");add(row,"span",name(g.code));
        const meter=add(row,"meter","");meter.max=Math.max(1,visible[0][metric]);meter.value=g[metric];
        meter.setAttribute("aria-label",`${name(g.code)}: ${fmt(g[metric])}`);add(row,"strong",fmt(g[metric]));
      }
      for (const g of sorted) {
        const row=add(body,"tr",""),button=add(add(row,"td",""),"button",name(g.code));button.type="button";
        buttons.set(g.code,button);button.addEventListener("click",()=>{selected=g.code;map?.focus(selected);detail();});
        for (const value of [fmt(g.alerts),pct(g.alerts,subset),fmt(g.rows)]) add(row,"td",value).className="num";
      }
      if (!visible.length) toggle.hidden=true;
      const segments=get("share-segments"), size=sorted.reduce((a,g)=>a+g[metric],0);
      segments.replaceChildren();let offset=0;
      for (const [k,g] of sorted.entries()) {
        const width=size?1000*g[metric]/size:0;
        if (width<=0) continue;
        const part=svg(segments,"rect",{x:offset,y:0,width,height:18,class:`share-band share-${k%6}${g.code==="unknown"?" share-unknown":""}`});
        svg(part,"title",{},`${name(g.code)}: ${pct(g[metric],size)}`);offset+=width;
      }
      get("share-note").textContent=size?`${name(sorted[0].code)} accounts for ${pct(sorted[0][metric],size)} of the displayed ${metric==="rows"?"source rows":"bucket alert count"}. See the table for exact values.`:"No nonzero share can be calculated for the selected metric.";
      map?.update(sorted.map(g=>({code:g.code,members:g.members,label:name(g.code),value:g[metric]})),metric,selected);
      detail();if (!chart.hidden) drawDepth(visible,metric);
    }
    sort.addEventListener("change",rerank);
    grouping.addEventListener("change",()=>{
      const combined=grouping.value!=="separate", active=groups.get(selected);
      groups=aggregate(snapshot,combined).groups;
      if (combined && chinaLabels.includes(selected)) selected="CN";
      else if (!combined && active?.members.length>1 && !groups.has(selected)) selected=active.members.find(code=>groups.has(code));
      rerank();
    });
    toggle.addEventListener("click",()=>{
      chart.hidden=!chart.hidden;get("chart-flat").hidden=!chart.hidden;
      toggle.setAttribute("aria-pressed",String(!chart.hidden));toggle.textContent=chart.hidden?"3D view":"2D view";
      if (!chart.hidden) drawDepth(visible,metric);
    });
    for (const id of ["country-angle","country-tilt"]) get(id).addEventListener("input",()=>drawDepth(visible,metric));
    rerank();get("workspace").hidden=false;
    // The fragment target was initially hidden while the snapshot loaded.
    const section=globalThis.location?.hash?.slice(1);
    if (["pulse-map","comparison","breakdown"].includes(section)) get(section).scrollIntoView();
  }
  async function json(path) {
    const res=await fetch(path,{cache:"no-store"});if (!res.ok) throw Error("missing public file");return res.json();
  }
  return Promise.all([json("data.json"),json("status.json").catch(()=>null)])
    .then(([snapshot,status])=>render(snapshot,status))
    .catch(()=>{get("workspace").hidden=true;get("country-batch").textContent="No verified public country comparison is available. Missing is not zero activity.";});
})();
