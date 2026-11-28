"use strict";
// Replay frames represent already published batches, not times of attacks.
const FlowTimeline=(()=>{
  const maxFrames=12;
  const count=n=>Number.isSafeInteger(n)&&n>=0;
  function parse(raw, known, now=Date.now()){
    if(raw?.schema_version!==1||Object.keys(raw).sort().join()!=="frames,schema_version"||
      !Array.isArray(raw.frames)||raw.frames.length>maxFrames)throw Error("Invalid replay index");
    let prior=-Infinity;
    for(const frame of raw.frames){
      if(!frame||Object.keys(frame).sort().join()!=="batch_utc,countries")throw Error("Invalid replay frame");
      const at=PublicView.utc(frame.batch_utc);
      if(!Number.isFinite(at)||at<=prior||at>now+600000||!Array.isArray(frame.countries)||frame.countries.length>20)throw Error("Invalid replay time or coverage");
      prior=at;let volume=0,rows=0;const seen=new Set();
      for(const part of frame.countries){
        if(!Array.isArray(part)||part.length!==3)throw Error("Invalid replay country");
        const [code,n,alerts]=part;
        if(!(code==="unknown"||known.has(code))||seen.has(code)||!count(n)||n<1||!count(alerts))throw Error("Invalid replay counts");
        seen.add(code);rows+=n;volume+=alerts;
      }
      if(rows>20||!count(volume))throw Error("Invalid replay total");
    }
    return raw.frames;
  }
  const eligible=(data,report,complete)=>{
    const d=PublicView.utc(data?.generated),r=PublicView.utc(report?.last_attempt_utc);
    return complete&&report?.state==="ok"&&!data?.public_revision&&Number.isFinite(d)&&Number.isFinite(r)&&d>=r-900000&&d<=r+900000;
  };
  function connect({known,render}){
    const el=id=>document.getElementById(id);
    const select=el("map-view"),slider=el("replay-position"),play=el("replay-play"),stamp=el("replay-stamp");
    const area=el("replay-controls"),message=el("map-view-note");
    const session=new Map();let archive=[],loading=null,archiveError=false,at=null,timer=null;
    const mode=()=>select.value==="live"?"live":select.value==="replay"?"replay":"snapshot";
    const frames=()=>[...new Map([...archive.map(f=>[f.batch_utc,f]),...session]).values()]
      .sort((a,b)=>a.batch_utc.localeCompare(b.batch_utc)).slice(-maxFrames);
    const reduced=()=>globalThis.matchMedia?.("(prefers-reduced-motion: reduce)")?.matches===true;
    function stop(){if(timer!==null)clearInterval(timer);timer=null;play.textContent="Play batches";}
    function sync(){
      const view=mode(),list=frames();let i=list.findIndex(f=>f.batch_utc===at);
      if(i<0)i=0;
      const frame=view==="replay"?list[i]||null:null;
      if(frame)at=frame.batch_utc;
      area.hidden=view!=="replay";
      const stepping=list.length>1;
      slider.max=String(Math.max(0,list.length-1));slider.value=String(i);slider.disabled=!stepping;
      slider.setAttribute("aria-valuetext",frame?.batch_utc||"No archived batches");
      el("replay-prev").disabled=!stepping||i===0;el("replay-next").disabled=!stepping||i>=list.length-1;play.disabled=!stepping;play.hidden=reduced();
      stamp.textContent=frame?`${frame.batch_utc} · batch ${i+1} of ${list.length}`:archiveError?"No verified archive available.":loading?"Loading archived batches…":"No eligible batch in this session.";
      message.textContent=view==="live"?"Live follow checks published snapshots every minute. Highlights mark new batches, not individual events.":view==="replay"?
        `Saved publication times, not event times. Seven-day source windows overlap. ${archiveError?"Archive unavailable; only batches verified in this tab may appear.":"Includes archived batches and new verified batches seen in this tab; gaps are possible."}`:
        "Latest published country snapshot. Optional pulse links are a ranked illustration, not network paths.";
      render(view,frame);
    }
    function step(i){const list=frames();if(i<0||i>=list.length)return false;at=list[i].batch_utc;sync();return true;}
    function fetchArchive(){
      if(loading)return loading;
      loading=(async()=>{
        try{
          const r=await fetch("map-replay.json",{cache:"no-store",signal:globalThis.AbortSignal?.timeout?.(12000)});
          if(!r.ok)throw Error("No archive");archive=parse(await r.json(),known);archiveError=false;
        }catch(_){archiveError=true;}
      })().finally(()=>{loading=null;if(mode()==="replay")sync();});
      return loading;
    }
    select.addEventListener("change",()=>{stop();if(mode()==="replay"&&!archive.length)fetchArchive();sync();});
    slider.addEventListener("input",()=>{stop();step(Number(slider.value));});
    el("replay-prev").addEventListener("click",()=>{stop();step(Number(slider.value)-1);});
    el("replay-next").addEventListener("click",()=>{stop();step(Number(slider.value)+1);});
    play.addEventListener("click",()=>{
      if(timer!==null){stop();return;}
      const list=frames();if(mode()!=="replay"||list.length<2||reduced())return;
      if(Number(slider.value)===list.length-1)step(0);
      play.textContent="Pause batches";
      timer=setInterval(()=>{if(!step(Number(slider.value)+1)||Number(slider.value)===frames().length-1)stop();},2200);
    });
    globalThis.matchMedia?.("(prefers-reduced-motion: reduce)")?.addEventListener?.("change",()=>{if(mode()==="replay"){stop();sync();}});
    globalThis.document?.addEventListener?.("visibilitychange",()=>{if(document.hidden)stop();});
    return {mode,record(frame){
      try{parse({schema_version:1,frames:[frame]},known);}catch(_){return;}
      const exists=frames().some(f=>f.batch_utc===frame.batch_utc);
      if(!exists){session.set(frame.batch_utc,frame);if(session.size>maxFrames)session.delete(session.keys().next().value);if(mode()==="replay")sync();}
    }};
  }
  return {parse,eligible,connect};
})();
