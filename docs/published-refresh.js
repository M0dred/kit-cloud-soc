"use strict";
// Read the static, privacy-reviewed Pages artifacts. Never poll the collectors.
function publishedRefresh({accept,paint,interval=60000}) {
  const get=id=>document.getElementById(id);
  const label=get("refresh-status"), button=get("refresh-now");
  let data=null,report=null,dataKey="",pending=null,started=false;
  async function load(path){
    const signal=globalThis.AbortSignal?.timeout?.(12000);
    const res=await fetch(path,{cache:"no-store",signal});
    if(!res.ok)throw Error("File unavailable");return res.json();
  }
  const time=s=>PublicView.utc(s);
  const validTime=t=>Number.isFinite(t)&&t<=Date.now()+600000;
  function usableReport(r){return r?.schema_version===1&&["ok","degraded","unknown"].includes(r.state)&&validTime(time(r.last_attempt_utc));}
  function acceptData(candidate){
    const next=time(candidate?.generated);
    if(!validTime(next)||!accept(candidate))return false;
    if(!data)return true;
    const previous=time(data.generated);
    if(next!==previous)return next>previous;
    if(JSON.stringify(candidate)===dataKey)return true;
    const revision=d=>d.public_revision?.kind==="projection_correction"?time(d.public_revision.corrected_utc):NaN;
    const newRevision=revision(candidate), oldRevision=revision(data);
    return validTime(newRevision)&&newRevision>=next&&(!Number.isFinite(oldRevision)||newRevision>oldRevision);
  }
  function setNotice(value){if(label)label.textContent=value;}
  function poll(){
    if(pending)return pending;
    button?.setAttribute("aria-busy","true");
    pending=(async()=>{
      const [batch,heartbeat]=await Promise.allSettled([load("data.json"),load("status.json")]);
      let batchOK=false, heartbeatOK=false, changed=false;
      try {batchOK=batch.status==="fulfilled"&&acceptData(batch.value);}catch(_){/* Malformed batch. */}
      if(batchOK){
        const key=JSON.stringify(batch.value);changed=key!==dataKey;
        if(changed){data=batch.value;dataKey=key;}
      }
      if(heartbeat.status==="fulfilled"&&usableReport(heartbeat.value)){
        const r=heartbeat.value, t=time(r.last_attempt_utc), last=report?time(report.last_attempt_utc):-Infinity;
        // A cached older heartbeat cannot reset the last verified result. Also
        // keep a known degradation on conflicting equal-minute responses.
        heartbeatOK=t>last||t===last&&!(report?.state==="degraded"&&r.state!=="degraded");
        if(heartbeatOK)report=r;
      }
      const complete=batchOK&&heartbeatOK;
      await paint({data,report,changed,complete});
      const at=new Date(Date.now()).toISOString().slice(11,19)+" UTC";
      setNotice(!data?`Checked ${at} · no verified batch available.`:
        complete?`Checked ${at} · ${changed?"published batch loaded":"no batch change"} · not live telemetry`:
        `Checked ${at} · refresh incomplete; keeping last verified values.`);
    })().catch(()=>setNotice("Display refresh failed. Reload to verify the published view.")).finally(()=>{
      pending=null;button?.setAttribute("aria-busy","false");
    });
    return pending;
  }
  function start(){
    if(started)return pending||Promise.resolve();started=true;
    button?.addEventListener("click",poll);
    if(typeof window!=="undefined"){
      const visible=()=>{if(!document.hidden)poll();};
      window.setInterval(visible,interval);
      document.addEventListener("visibilitychange",visible);
    }
    return poll();
  }
  return {start,poll};
}
