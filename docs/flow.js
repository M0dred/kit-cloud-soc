"use strict";
// Entirely fictional. Source addresses are RFC 5737 examples; no live data is read.
(() => {
  const sources = [
    {id:"s1", label:"192.0.2.24", point:[-228, 91, 52]},
    {id:"s2", label:"198.51.100.37", point:[-228, 0, -57]},
    {id:"s3", label:"203.0.113.82", point:[-228, -93, 47]},
  ];
  const sensors = [
    {id:"a", label:"Wazuh Demo A", point:[228, 91, -37]},
    {id:"b", label:"Wazuh Demo B", point:[228, 0, 63]},
    {id:"c", label:"Clear NDR Demo", point:[228, -93, -46]},
  ];
  const events = [
    {at:"06:00:04", from:"s1", to:"a", behavior:"SSH authentication event", result:"Rejected in this example; no successful access shown."},
    {at:"06:00:12", from:"s2", to:"c", behavior:"Inbound session record", result:"Network observation only; application outcome unknown."},
    {at:"06:00:23", from:"s3", to:"b", behavior:"HTTP request alert", result:"HTTP error in this example; exploitation not established."},
    {at:"06:00:38", from:"s2", to:"a", behavior:"SSH authentication event", result:"Rejected in this example; no successful access shown."},
    {at:"06:00:49", from:"s1", to:"c", behavior:"Inbound session record", result:"Separate observation; shared source does not prove the same session or target."},
    {at:"06:01:04", from:"s3", to:"b", behavior:"Follow-up HTTP request alert", result:"Application outcome and destination asset not verified."},
  ];
  const nodes = [...sources, ...sensors];
  const byNode = new Map(nodes.map(node => [node.id, node]));
  const get = id => document.getElementById(id);
  const svg = (parent, tag, attrs, text) => {
    const el = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (const [key, val] of Object.entries(attrs)) el.setAttribute(key, String(val));
    if (text !== undefined) el.textContent = text;
    parent.appendChild(el);
    return el;
  };
  const clamp = (n, low, high) => Math.min(high, Math.max(low, n));
  const round = n => Math.round(n*10)/10;
  const stamp = event => `2030-01-01 ${event.at} UTC`;
  const displayIp = ip => ip.replace(/\.(?=\d+$)/, "[.]");
  let step = 0, flat = false, timer = null;

  // A small perspective projection: yaw about Y, then tilt about X. The same
  // fictional coordinates become a flat XY view on request; no WebGL required.
  function project([x, y, z]) {
    if (flat) return [370+x, 158-y, 0];
    const angle = clamp(Number(get("angle").value) || 0, -38, 38) * Math.PI / 180;
    const yawX = x*Math.cos(angle) - z*Math.sin(angle);
    const yawZ = x*Math.sin(angle) + z*Math.cos(angle);
    const tilt = 0.20;
    const cameraY = y*Math.cos(tilt) - yawZ*Math.sin(tilt);
    const depth = y*Math.sin(tilt) + yawZ*Math.cos(tilt);
    const scale = 940/(940+depth);
    return [round(370+yawX*scale), round(158-cameraY*scale), depth];
  }
  function renderScene() {
    const active = events[step];
    const pts = new Map(nodes.map(node => [node.id, project(node.point)]));
    const plane = get("plane"), edges = get("edges"), layer = get("nodes");
    plane.replaceChildren(); edges.replaceChildren(); layer.replaceChildren();
    const guide = (a, b) => svg(plane, "path", {class:"guides", d:`M ${project(a).slice(0,2).join(" ")} L ${project(b).slice(0,2).join(" ")}`});
    for (const x of [-250,-125,0,125,250]) guide([x,-112,-122], [x,-112,142]);
    for (const z of [-122,-56,10,76,142]) guide([-250,-112,z], [250,-112,z]);
    const drawEdge = (event, selected) => {
      const [x1,y1] = pts.get(event.from), [x2,y2] = pts.get(event.to);
      const sense = Math.sign(x2-x1) || 1;
      const start = x1 + 13*sense, stop = x2 - 17*sense;
      const middle = round((start+stop)/2);
      const d = `M ${start} ${y1} C ${middle} ${y1}, ${middle} ${y2}, ${stop} ${y2}`;
      const attrs = {class:selected?"active":"earlier",d};
      if (selected) attrs["marker-end"] = "url(#flow-arrow)";
      svg(edges,"path",attrs);
      if (selected && timer !== null) svg(edges,"path",{class:"trace",d});
    };
    const currentKey = `${active.from}:${active.to}`;
    const prior = new Map(events.slice(0,step).map(event => [`${event.from}:${event.to}`,event]));
    prior.delete(currentKey);
    for (const event of prior.values()) drawEdge(event,false);
    drawEdge(active,true);
    const ordered = [...nodes].sort((a,b) => pts.get(b.id)[2]-pts.get(a.id)[2]);
    for (const node of ordered) {
      const [x,y] = pts.get(node.id);
      const selected = node.id === active.from || node.id === active.to ? " selected-node" : "";
      const source = node.id.startsWith("s");
      if (source) svg(layer,"circle",{cx:x,cy:y,r:11,class:"source-node"+selected});
      else svg(layer,"rect",{x:x-12,y:y-12,width:24,height:24,rx:4,class:"sensor-node"+selected});
      svg(layer,"text",{x,y:y+34,class:"node-label"},source?displayIp(node.label):node.label);
    }
    get("scene-description").textContent = `Fictional IP ${displayIp(byNode.get(active.from).label)} was recorded by ${byNode.get(active.to).label}. Target and compromise not established.`;
  }
  function render() {
    const event = events[step];
    get("step").value = String(step+1);
    get("step").setAttribute("aria-valuetext",`${step+1} of ${events.length}, ${stamp(event)}`);
    get("step-label").textContent = `Event ${step+1} of ${events.length} · ${stamp(event)} (fictional)`;
    get("observed-source").textContent = displayIp(byNode.get(event.from).label);
    get("observer").textContent = byNode.get(event.to).label;
    get("behavior").textContent = event.behavior;
    get("result").textContent = event.result;
    get("previous").disabled = step===0;
    get("next").disabled = step===events.length-1;
    get("play").textContent = timer!==null?"Pause":step===events.length-1?"Replay":"Play";
    for (const [index, button] of buttons.entries()) button.setAttribute("aria-pressed",String(index===step));
    renderScene();
  }
  function pause() {
    if (timer!==null) clearInterval(timer);
    timer=null;
  }
  function go(index) {
    pause();
    step=clamp(index,0,events.length-1);
    render();
  }
  const buttons = events.map((event,index) => {
    const li=document.createElement("li"), button=document.createElement("button");
    button.type="button";
    button.textContent=`${event.at} UTC · ${displayIp(byNode.get(event.from).label)} → ${byNode.get(event.to).label}`;
    button.addEventListener("click",()=>go(index));
    li.appendChild(button);get("event-list").appendChild(li);
    return button;
  });
  get("step").max=String(events.length);
  get("step").addEventListener("input",()=>go(Number(get("step").value)-1));
  get("previous").addEventListener("click",()=>go(step-1));
  get("next").addEventListener("click",()=>go(step+1));
  get("play").addEventListener("click",()=>{
    if (timer!==null) {pause();render();return;}
    if (step===events.length-1) step=0;
    timer=setInterval(()=>{
      step+=1;
      if (step>=events.length-1) {step=events.length-1;pause();}
      render();
    },2000);  // Stepped demo schedule; not real-time packet timing.
    render();
  });
  get("angle").addEventListener("input",()=>{
    get("angle-label").textContent=`${get("angle").value}°`;
    renderScene();
  });
  get("flat").addEventListener("click",()=>{
    flat=!flat;
    get("flat").setAttribute("aria-pressed",String(flat));
    get("angle").disabled=flat;
    renderScene();
  });
  render();
  get("replay").hidden=false;
})();
