"use strict";
// Shared semantics for the public brief, atlas, and activity report.
const PublicView = (()=>{
  const H=3600000, day=24*H, grace=30*60000, hours=[6,12,18,22];
  function utc(s) {
    if (typeof s!=="string" || !/^\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC$/.test(s)) return NaN;
    const t=Date.parse(s.replace(" ","T").replace(" UTC","Z"));
    return Number.isFinite(t)&&stamp(t)===s?t:NaN;
  }
  const stamp=t=>new Date(t).toISOString().slice(0,16).replace("T"," ")+" UTC";
  function due(now) {
    const cutoff=now-grace, midnight=Math.floor(cutoff/day)*day;
    const slot=[...hours].reverse().map(h=>midnight+h*H).find(t=>t<=cutoff);
    return slot??midnight-day+22*H;
  }
  function status(batch, report, now=Date.now(), verified=true) {
    const b=utc(batch), t=utc(report?.last_attempt_utc), expected=due(now);
    const validBatch=Number.isFinite(b)&&b<=now+600000;
    const valid=report?.schema_version===1&&["ok","degraded","unknown"].includes(report.state)&&Number.isFinite(t)&&t<=now+600000;
    const last=valid?report.state:"unknown";
    const overdue=valid&&t<expected;
    const stale=validBatch&&now-b>day;
    const ago=validBatch?Math.max(0,Math.floor((now-b)/H)):null;
    const batchText=validBatch?`Snapshot ${batch} · ${ago}h old${stale?" · stale":""}`:"Snapshot time unknown";
    const attempt=valid?`Last attempt ${report.last_attempt_utc} · ${last}`:"Last attempt unknown";
    const heartbeat=overdue?`Heartbeat overdue · ${stamp(expected)} slot unconfirmed`:
      !valid||last==="unknown"?"Scheduled heartbeat unverified":"";
    const latest=heartbeat?`${attempt}. ${heartbeat}.`:`${attempt}.`;
    let pill="LAST RUN OK", note="Latest published batch snapshot (not live). Alert counts are not incidents.";
    if (!validBatch||!valid||last==="unknown") {pill="STATUS UNKNOWN";note="Last run or batch status is unverified. This is not live detection.";}
    else if (stale) {pill="STALE SNAPSHOT";note="Snapshot older than 24h. Do not treat these counts as current.";}
    else if (overdue) {pill="HEARTBEAT OVERDUE";note=heartbeat+". The last known result does not confirm the latest scheduled slot.";}
    else if (last==="degraded") {pill="PIPELINE DEGRADED";note="Showing the last published snapshot. Coverage may be incomplete; failure details stay private.";}
    else if (b<t-15*60000) {pill="SNAPSHOT LAGS RUN";note="The last pipeline status is newer than displayed data; verify the batch before using these counts.";}
    else if (t<b-15*60000) {pill="STATUS MISMATCH";note="The heartbeat is older than the displayed data; the latest batch status is not verified.";}
    if (!verified&&pill==="LAST RUN OK") {pill="REFRESH UNVERIFIED";note="Current refresh incomplete. Showing last verified published values.";}
    return {pill,note,batchText,attempt,heartbeat,latest,overdue,stale};
  }
  const ssh="SSH-related alert (outcome unverified)";
  function sampleLabel(value) {
    if (["SSH authentication alert",ssh].includes(value)) return ssh;
    return ["Web request alert (outcome unverified)","Other detection (sample only)"].includes(value)?value:"No alert sample available";
  }
  return Object.freeze({utc,due,status,sampleLabel});
})();
