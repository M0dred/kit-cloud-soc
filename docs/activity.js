"use strict";
// Only consumes aggregate fields from the two existing public, same-origin files.
(() => {
  const get = id => document.getElementById(id);
  const dayMs = 86400000;
  const count = n => Number.isSafeInteger(n) && n >= 0;
  const fmt = n => n.toLocaleString();
  const asDate = ms => new Date(ms).toISOString().slice(0, 10);
  function utc(stamp) {
    if (typeof stamp !== "string" || !/^\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC$/.test(stamp)) return NaN;
    const ms = Date.parse(stamp.replace(" ", "T").replace(" UTC", "Z"));
    return Number.isFinite(ms) && new Date(ms).toISOString().slice(0, 16).replace("T", " ")+" UTC" === stamp ? ms : NaN;
  }
  const clamp = (value, min, max) => Math.max(min, Math.min(max, value));
  const add = (parent, tag, text) => {
    const el = document.createElement(tag);
    el.textContent = text;
    parent.appendChild(el);
    return el;
  };
  const svg = (parent, tag, attrs, text) => {
    const el = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (const [key, value] of Object.entries(attrs)) el.setAttribute(key, String(value));
    if (text !== undefined) el.textContent = text;
    parent.appendChild(el);
    return el;
  };
  const level = (n, top) => n===null?"heat-unknown":n===0?"heat-0":`heat-${Math.ceil(5*n/top)}`;
  async function getJson(path) {
    const response = await fetch(path, {cache:"no-store"});
    if (!response.ok) throw Error("public file unavailable");
    return response.json();
  }
  function buckets(snapshot, time) {
    const published = snapshot.wazuh?.by_day;
    if (!Array.isArray(published) || published.length>8) throw Error("invalid daily buckets");
    const end = Math.floor(time/dayMs)*dayMs;
    const dates = new Map(Array.from({length:8}, (_, i) => [asDate(end-(7-i)*dayMs),null]));
    const seen = new Set();
    for (const row of published) {
      if (!Array.isArray(row) || row.length!==2 || !dates.has(row[0]) || seen.has(row[0]) ||
          !(row[1]===null || count(row[1]))) throw Error("invalid daily bucket");
      dates.set(row[0], row[1]);
      seen.add(row[0]);
    }
    return [...dates].map(([date,n],index) => ({date,n,edge:index===0||index===dates.size-1}));
  }
  function heartbeat(report, batchTime, now) {
    const time=utc(report?.last_attempt_utc);
    if (report?.schema_version!==1 || !["ok","degraded","unknown"].includes(report.state) ||
        !Number.isFinite(time) || time>now+600000) return "Pipeline heartbeat unavailable; not a live chart.";
    const label=`Last reported attempt: ${report.last_attempt_utc} · ${report.state}.`;
    if (time<batchTime-15*60000) return `${label} The heartbeat is older than this batch; publication status is unverified.`;
    if (now-time>dayMs) return `${label} The heartbeat is over 24 hours old.`;
    if (report.state==="degraded") return `${label} This is the last available published batch, not a fresh run.`;
    if (time>batchTime+15*60000) return `${label} This chart's batch is older than that attempt.`;
    return label;
  }
  function drawColumns(days, top) {
    const turn=clamp(Number(get("azimuth").value)||0,-35,35), tilt=clamp(Number(get("elevation").value)||24,12,35);
    get("azimuth-value").textContent=`${turn}°`;
    get("elevation-value").textContent=`${tilt}°`;
    const [yaw,pitch]=[turn,tilt].map(a=>a*Math.PI/180);
    const project=([x,y,z])=>{
      const east=x*Math.cos(yaw)+z*Math.sin(yaw), depth=z*Math.cos(yaw)-x*Math.sin(yaw);
      return [360+east, 216-y*Math.cos(pitch)+depth*Math.sin(pitch)].map(n=>Math.round(n*10)/10).join(",");
    };
    const grid=get("volume-grid"), plot=get("volume-bars");
    grid.replaceChildren();plot.replaceChildren();
    const guide=(a,b)=>svg(grid,"polyline",{points:`${project(a)} ${project(b)}`,class:"volume-guide"});
    const axisLevels=top>0?[0,top/2,top]:[0];
    const height=n=>top>0?140*n/top:0;
    for (const value of axisLevels) {
      const y=height(value);
      guide([-254,y,-31],[254,y,-31]);
      const [x,screenY]=project([-259,y,-31]).split(",");
      svg(grid,"text",{x,y:Number(screenY)+4,class:"volume-tick"},fmt(Math.round(value)));
    }
    const layout=days.map((day,i)=>({...day,x:-224+64*i}));
    const face=(points,theme,shade="")=>svg(plot,"polygon",{points:points.map(project).join(" "),class:`volume-face ${theme} ${shade}`});
    const ordered=(turn>=0?[...layout].reverse():layout);
    for (const {x,n} of ordered) {
      if (n===null) continue; // No column for missing, and no exaggerated minimum height for zero.
      const y=height(n), [l,r]=[x-18,x+18], [back,front]=[-18,18], tone=level(n,top);
      if (y>0) {
        const side=turn>=0?l:r;
        face([[side,0,front],[side,0,back],[side,y,back],[side,y,front]],tone,"volume-side");
        face([[l,0,front],[r,0,front],[r,y,front],[l,y,front]],tone);
      }
      face([[l,y,front],[r,y,front],[r,y,back],[l,y,back]],tone,"volume-top");
    }
    for (const {x,date} of layout) {
      const [sx,sy]=project([x,0,42]).split(",");
      svg(plot,"text",{x:sx,y:Number(sy)+14,class:"volume-date"},date.slice(5));
    }
  }
  function render(snapshot,report) {
    const now=Date.now(), batch=utc(snapshot?.generated);
    if (!Number.isFinite(batch) || batch>now+600000) throw Error("invalid public timestamp");
    const rows=buckets(snapshot,batch), seen=rows.filter(day=>day.n!==null);
    const max=Math.max(0,...seen.map(day=>day.n));
    const sum=seen.reduce((a,day)=>a+day.n,0), total=snapshot.wazuh?.total_7d;
    const agrees=seen.length===rows.length && count(total) && sum===total;
    const stale=now-batch>dayMs?" This snapshot is over 24 hours old.":"";
    get("batch-status").textContent=`Published batch: ${snapshot.generated}.${stale}`;
    get("heartbeat").textContent=heartbeat(report,batch,now);
    const countNote=count(total)?`Published 7-day total: ${fmt(total)} alerts.`:"7-day total unavailable.";
    const caveat=agrees?"Daily counts reconcile to the total.":seen.length<rows.length?
      "Daily coverage is incomplete; missing is not zero.":"Daily values cannot be reconciled to a verified seven-day total.";
    get("coverage").textContent=`${countNote} ${caveat} First and last UTC dates may be partial.`;
    const list=get("heat-grid");list.replaceChildren();
    for (const {date,n,edge} of rows) {
      const tile=add(list,"li","");tile.className=level(n,max);
      const time=add(tile,"time",date);time.setAttribute("datetime",date);
      add(tile,"strong",n===null?"N/A":fmt(n));
      add(tile,"small",n===null?"No published value":edge?"Alerts · may be partial":"Alerts");
    }
    get("heat-scale").textContent=seen.length===0?"No daily counts available.":max===0?
      "Published daily counts shown here are zero; missing cells are separate.":
      `Color is relative to this batch: 0 to ${fmt(max)} alerts. Hatched cells mean no published value. Use numbers for comparison.`;
    if (seen.length===0) return;
    const toggle=get("show-columns"), controls=get("columns");toggle.hidden=false;
    toggle.addEventListener("click",()=>{
      controls.hidden=!controls.hidden;
      toggle.textContent=controls.hidden?"Show 3D columns":"Hide 3D columns";
      toggle.setAttribute("aria-expanded",String(!controls.hidden));
      if (!controls.hidden) drawColumns(rows,max);
    });
    for (const id of ["azimuth","elevation"]) get(id).addEventListener("input",()=>drawColumns(rows,max));
  }
  return Promise.all([getJson("data.json"),getJson("status.json").catch(()=>null)])
    .then(([data,report])=>render(data,report))
    .catch(()=>{get("batch-status").textContent="No verified public daily batch is available. Do not infer zero activity.";});
})();
