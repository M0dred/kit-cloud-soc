"use strict";
// An optional, aggregate-only layer, verified against the exact published snapshot bytes.
function createSubdivisionPanel(batch, snapshotHash) {
  const get=id=>document.getElementById(id), count=n=>Number.isSafeInteger(n)&&n>=0;
  const fmt=n=>n.toLocaleString();
  const add=(root,tag,text)=>{const el=document.createElement(tag);el.textContent=text;root.appendChild(el);return el;};
  const status=get("subdivision-status"), panel=get("subdivision-profile");
  let selection=null, result=null, available=false, finished=false;
  const stamp=s=>typeof s==="string"&&/^\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC$/.test(s)&&Number.isFinite(Date.parse(s.replace(" ","T").replace(" UTC","Z")));
  const keys=(o,fields)=>o && typeof o==="object" && !Array.isArray(o) && Object.keys(o).length===fields.length && fields.every(k=>Object.hasOwn(o,k));
  function partition(item, rows, alerts, code) {
    if (!keys(item,["subdivisions","withheld_rows","withheld_alerts"]) || !Array.isArray(item.subdivisions) ||
        item.subdivisions.length>6 || !count(item.withheld_rows) || !count(item.withheld_alerts) ||
        (code==="unknown"&&item.subdivisions.length)) throw Error("invalid state projection");
    let r=item.withheld_rows,a=item.withheld_alerts;
    const seen=new Set();
    for (const state of item.subdivisions) {
      if (!keys(state,["name","rows","alerts"]) || typeof state.name!=="string" || !/^\p{L}[\p{L}\p{M} .,'’()&-]{0,71}$/u.test(state.name) ||
          seen.has(state.name) || !count(state.rows) || state.rows<3 || !count(state.alerts)) throw Error("invalid state cell");
      seen.add(state.name);r+=state.rows;a+=state.alerts;
    }
    if (r!==rows || a!==alerts) throw Error("unreconciled state counts");
    return item;
  }
  function render() {
    panel.replaceChildren();
    if (!finished) {status.textContent="Checking the optional regional aggregate…";return;}
    if (!available) {status.textContent="No verified subdivision profile for this exact batch. Missing is not zero.";return;}
    if (!selection?.length) {status.textContent="Select a country with published source rows.";return;}
    try {
      // Validate the selection before rendering any numbers, even if the file cached mid-deploy.
      const rows=selection.map(item=>({...item,group:item.rows?partition(result.countries[item.code],item.rows,item.alerts,item.code):null}));
      status.textContent=`Approximate IP subdivision · DB-IP City Lite built ${result.database_build_utc} · minimum 3 distinct source rows per named region.`;
      for (const item of rows) {
        add(panel,"h3",item.name);
        if (!item.group) {add(panel,"p","No published source rows for this original country label in the batch.");continue;}
        const table=add(panel,"table","");table.setAttribute("aria-label",`Subdivision totals for ${item.name}`);
        const head=add(add(table,"thead",""),"tr","");
        for (const h of ["Subdivision","Source rows","Bucket alerts"]) add(head,"th",h).setAttribute("scope","col");
        const body=add(table,"tbody","");
        const row=(name,num,alerts)=>{
          const tr=add(body,"tr","");add(tr,"th",name).setAttribute("scope","row");
          add(tr,"td",fmt(num));add(tr,"td",fmt(alerts));
        };
        for (const cell of item.group.subdivisions) row(cell.name,cell.rows,cell.alerts);
        if (item.group.withheld_rows) row("Not subdivided",item.group.withheld_rows,item.group.withheld_alerts);
        if (!item.group.subdivisions.length) add(panel,"p","No state/province group meets the publishing threshold in this country subset.");
      }
    } catch (_) {panel.replaceChildren();status.textContent="Subdivision counts do not reconcile with this selection; unavailable.";}
  }
  const ready=(async()=>{
    try {
      if (typeof snapshotHash!=="string" || !/^[0-9a-f]{64}$/.test(snapshotHash)) throw Error("no snapshot digest");
      const res=await fetch("subdivisions.json",{cache:"no-store"});if (!res.ok) throw Error("unavailable");
      result=await res.json();
      available=keys(result,["schema_version","batch_utc","snapshot_sha256","minimum_rows","database_build_utc","countries"]) &&
        result.schema_version===1 && result.batch_utc===batch && result.snapshot_sha256===snapshotHash && result.minimum_rows===3 &&
        stamp(result.database_build_utc) && result.countries!==null && typeof result.countries==="object" && !Array.isArray(result.countries);
    } catch (_) {available=false;}
    finished=true;render();
  })();
  return {ready,focus(rows){selection=rows;render();}};
}
