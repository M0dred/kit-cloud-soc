"use strict";
(function(global){
const byId=id=>document.getElementById(id);
const number=v=>Number.isFinite(Number(v))?Number(v):null;
const format=n=>number(n)===null?"N/A":Number(n).toLocaleString();
const compact=n=>{const v=number(n);if(v===null)return"N/A";if(v>=1e9)return(v/1e9).toFixed(1)+"B";if(v>=1e6)return(v/1e6).toFixed(1)+"M";if(v>=1e3)return(v/1e3).toFixed(1)+"K";return v.toLocaleString();};
const percent=(v,d=1)=>number(v)===null?"N/A":Number(v).toFixed(d)+"%";
const ratioPercent=(v,d=1)=>number(v)===null?"N/A":(Number(v)*100).toFixed(d)+"%";
const colors={healthy:0x2dd4bf,attention:0xf59e0b,stale:0xef4444,unknown:0x94a3b8};
const cssColors={healthy:"#2dd4bf",attention:"#f59e0b",stale:"#ef4444",unknown:"#94a3b8"};
const statusLabel=s=>s==="healthy"?"healthy":s==="attention"?"attention":s==="stale"?"stale":"unknown";
const NODE_DEFS=[
 {id:"wazuh",name:"Wazuh",layer:"Sources",pos:[-7,1.5,0],desc:"Host, FIM, authentication and configuration telemetry.",status:d=>d.security_logs.status,metrics:d=>[["Security log state",statusLabel(d.security_logs.status)],["Coverage gap",format(d.security_logs.coverage_gap_days)+" days"]]},
 {id:"suricata",name:"Suricata",layer:"Sources",pos:[-7,-1.3,0],desc:"Network detection, alerts and protocol metadata.",status:d=>d.security_logs.status,metrics:d=>[["Alert documents",compact(d.security_logs.alert_documents)],["Top signature share",percent(d.security_logs.top_signature_share_pct,2)]]},
 {id:"misp",name:"MISP",layer:"Sources",pos:[-7,0,2.7],desc:"Threat-intelligence context and IOC enrichment.",status:()=>"unknown",metrics:d=>[["RAG intel events",format(d.rag.poc_alerts)],["Fresh context","not verified"]]},
 {id:"ingestion",name:"Ingestion",layer:"Pipeline",pos:[-3,0,0],desc:"Collection, normalization and checkpointing.",status:d=>d.cluster.status,metrics:d=>[["Cluster state",statusLabel(d.cluster.status)],["Nodes ready",format(d.cluster.nodes_ready)+" / "+format(d.cluster.nodes_total)]]},
 {id:"dlq",name:"DLQ",layer:"Pipeline",pos:[-3,-2.1,1.4],desc:"Failed records awaiting replay or resolution.",status:d=>d.rag.dlq_unresolved>0?"attention":"healthy",metrics:d=>[["Unresolved records",format(d.rag.dlq_unresolved)],["Case backlog",format(d.rag.case_backlog)]]},
 {id:"opensearch",name:"OpenSearch",layer:"Stores",pos:[1,1.4,0],desc:"Security event, alert and anomaly index store.",status:d=>d.security_logs.status,metrics:d=>[["Indexed documents",compact(d.security_logs.indexed_documents)],["Arkime capture",d.security_logs.arkime_capture_active?"active":"inactive"]]},
 {id:"clickhouse",name:"ClickHouse",layer:"Stores",pos:[1,-1.3,0],desc:"Asset, port, exposure and Agent-session analytics.",status:d=>d.asset_intel.status,metrics:d=>[["Unique asset IPs",compact(d.asset_intel.unique_ips)],["Data age",format(d.asset_intel.stale_days)+" days"]]},
 {id:"rag",name:"Security RAG",layer:"Intelligence",pos:[5,1.3,0],desc:"Embedding, retrieval and evidence context.",status:d=>d.rag.status,metrics:d=>[["Events",compact(d.rag.events)],["Recall@5",ratioPercent(d.rag.recall_at5,1)],["Embedding coverage",percent(d.rag.embedding_coverage_pct,2)]]},
 {id:"cases",name:"Cases",layer:"Intelligence",pos:[5,-1.3,0],desc:"Case aggregation, triage and evidence bundles.",status:d=>d.rag.status,metrics:d=>[["Cases",compact(d.rag.cases)],["Active",format(d.rag.case_status?.active||0)],["Human feedback",format(d.rag.feedback)]]},
 {id:"gateway",name:"AI Gateway",layer:"AI",pos:[9,1.2,0],desc:"Model routing, audit and provider health.",status:d=>d.ai.status,metrics:d=>[["Audit requests",compact(d.ai.audit_requests)],["Success rate",percent(d.ai.success_rate_pct,2)],["Gateway errors",percent(d.ai.gateway_error_rate_pct,2)]]},
 {id:"agents",name:"Agents",layer:"AI",pos:[9,-1.3,0],desc:"Agent sessions, tool use and cost records.",status:d=>d.ai.status,metrics:d=>[["Sessions",format(d.agent_sessions.sessions)],["Messages",compact(d.agent_sessions.messages)],["Recorded cost",Number(d.agent_sessions.recorded_cost||0).toFixed(2)]]},
 {id:"analyst",name:"Analyst",layer:"Consumer",pos:[13,0,0],desc:"Human review, decisions and approved response.",status:()=>"healthy",metrics:()=>[["Mode","human approval"],["Automation","read-only"]]}
];
const EDGE_DEFS=[
 ["wazuh","ingestion",1],["suricata","ingestion",2],["misp","ingestion",1],
 ["ingestion","opensearch",2],["ingestion","clickhouse",1],["ingestion","dlq",1],["dlq","ingestion",1],
 ["opensearch","rag",2],["clickhouse","rag",1],["rag","cases",2],["rag","gateway",1],["cases","analyst",1],["gateway","agents",1],["gateway","analyst",1]
];
function buildGraph(data){
 const nodes=NODE_DEFS.map(def=>({...def,state:statusLabel(def.status(data))}));
 const edges=EDGE_DEFS.map(([from,to,weight])=>({from,to,weight,active:!(from==="dlq"&&!data.rag.dlq_unresolved)&&!(to==="dlq"&&!data.rag.dlq_unresolved)}));
 return {nodes,edges};
}
function add(parent,tag,text,css=""){const el=document.createElement(tag);el.textContent=String(text);if(css)el.className=css;parent.appendChild(el);return el;}
function setBadge(id,status){const el=byId(id);el.textContent=statusLabel(status);el.className="cc-badge "+(status==="healthy"?"healthy":status==="attention"||status==="stale"?"attention":"");}
function metrics(id,items){const root=byId(id);root.replaceChildren();for(const [label,value] of items){const card=add(root,"div","","cc-metric");add(card,"span",label);add(card,"strong",value);}}
function renderNodeList(graph,select){
 const root=byId("node-list");root.replaceChildren();
 for(const node of graph.nodes){const button=add(root,"button","","observatory-node "+node.state);button.type="button";button.setAttribute("aria-pressed","false");button.dataset.node=node.id;add(button,"strong",node.name);add(button,"span",node.layer+" · "+node.state);button.addEventListener("click",()=>select(node.id));}
}
function selectNode(id,graph,visual){
 const node=graph.nodes.find(n=>n.id===id);if(!node)return;
 byId("detail-title").textContent=node.name;setBadge("detail-status",node.state);byId("detail-description").textContent=node.desc;metrics("detail-metrics",node.metrics(visual.data));
 const connections=graph.edges.filter(e=>e.from===id||e.to===id).map(e=>e.from===id?"to "+graph.nodes.find(n=>n.id===e.to).name:"from "+graph.nodes.find(n=>n.id===e.from).name);
 byId("detail-connections").textContent="Connections: "+(connections.join(" · ")||"none");
 for(const button of byId("node-list").querySelectorAll("button"))button.setAttribute("aria-pressed",String(button.dataset.node===id));
 for(const [key,item] of visual.nodeObjects)item.label.classList.toggle("selected",key===id);
 visual.selected=id;
}
function initModel(data){
 const graph=buildGraph(data);
 byId("generated").textContent="Generated "+data.generated_utc;
 const states=graph.nodes.map(n=>n.state);const overall=states.every(s=>s==="healthy")?"healthy":"attention";setBadge("overall-status",overall);
 byId("snapshot-note").textContent=overall==="healthy"?"All published aggregate nodes are healthy. This does not prove complete coverage.":"One or more platform domains need attention. Select a node to inspect aggregate evidence.";
 const visual={data,graph,nodeObjects:new Map(),edgeObjects:[],selected:null,motion:!global.matchMedia?.("(prefers-reduced-motion: reduce)")?.matches,labels:true,world:null,renderer:null,scene:null,camera:null};
 renderNodeList(graph,id=>selectNode(id,graph,visual));selectNode("rag",graph,visual);
 return {graph,visual};
}
function setupScene(visual){
 if(!global.THREE)throw new Error("Three.js failed to load");
 const THREE=global.THREE,host=byId("scene");
 const renderer=new THREE.WebGLRenderer({antialias:true,alpha:true,powerPreference:"high-performance"});
 renderer.setPixelRatio(Math.min(global.devicePixelRatio||1,2));renderer.setSize(host.clientWidth,host.clientHeight);renderer.setClearColor(0x000000,0);host.appendChild(renderer.domElement);
 const scene=new THREE.Scene();scene.fog=new THREE.FogExp2(0x071019,0.018);
 const camera=new THREE.PerspectiveCamera(48,host.clientWidth/host.clientHeight,0.1,100);camera.position.set(1,7.5,23);camera.lookAt(1,0,0);
 const world=new THREE.Group();scene.add(world);visual.renderer=renderer;visual.scene=scene;visual.camera=camera;visual.world=world;
 const grid=new THREE.GridHelper(32,32,0x1d4a5a,0x102633);grid.position.y=-3.2;world.add(grid);
 let seed=1337;const rand=()=>{seed=(seed*16807)%2147483647;return(seed-1)/2147483646;};
 const starPositions=[];for(let i=0;i<320;i++)starPositions.push((rand()-.5)*45,(rand()-.5)*24,(rand()-.5)*35-8);
 const starGeometry=new THREE.BufferGeometry();starGeometry.setAttribute("position",new THREE.Float32BufferAttribute(starPositions,3));const stars=new THREE.Points(starGeometry,new THREE.PointsMaterial({color:0x5f8294,size:0.035,transparent:true,opacity:.55}));scene.add(stars);
 const nodeGeometry=new THREE.IcosahedronGeometry(.42,1),ringGeometry=new THREE.TorusGeometry(.64,.025,8,48);
 for(const node of visual.graph.nodes){
  const material=new THREE.MeshBasicMaterial({color:colors[node.state]});const mesh=new THREE.Mesh(nodeGeometry,material);mesh.position.set(...node.pos);mesh.userData.nodeId=node.id;world.add(mesh);
  const ring=new THREE.Mesh(ringGeometry,new THREE.MeshBasicMaterial({color:colors[node.state],transparent:true,opacity:.45}));ring.position.copy(mesh.position);world.add(ring);
  const label=add(byId("labels"),"div",node.name,"observatory-label "+node.state);label.dataset.node=node.id;visual.nodeObjects.set(node.id,{mesh,ring,label,def:node});
 }
 for(const edge of visual.graph.edges){
  const from=visual.nodeObjects.get(edge.from).mesh.position,to=visual.nodeObjects.get(edge.to).mesh.position;
  const midpoint=from.clone().add(to).multiplyScalar(.5);midpoint.y+=edge.from==="dlq"||edge.to==="dlq"?-.5:.75;midpoint.z+=edge.from==="misp"?.8:0;
  const curve=new THREE.QuadraticBezierCurve3(from,midpoint,to);const geometry=new THREE.BufferGeometry().setFromPoints(curve.getPoints(40));
  const color=colors[visual.nodeObjects.get(edge.from).def.state];const line=new THREE.Line(geometry,new THREE.LineBasicMaterial({color,transparent:true,opacity:edge.active?.34:.12}));world.add(line);
  const particles=[];for(let i=0;i<Math.min(3,edge.weight+1);i++){const particle=new THREE.Mesh(new THREE.SphereGeometry(.065,8,8),new THREE.MeshBasicMaterial({color,transparent:true,opacity:edge.active?.9:.2}));world.add(particle);particles.push({mesh:particle,offset:i/Math.min(3,edge.weight+1),speed:.045+edge.weight*.015});}
  visual.edgeObjects.push({curve,line,particles,active:edge.active});
 }
 const raycaster=new THREE.Raycaster(),pointer=new THREE.Vector2();let drag=null;
 renderer.domElement.addEventListener("pointerdown",event=>{drag={x:event.clientX,y:event.clientY,moved:false};renderer.domElement.setPointerCapture(event.pointerId);});
 renderer.domElement.addEventListener("pointermove",event=>{if(!drag)return;const dx=event.clientX-drag.x,dy=event.clientY-drag.y;if(Math.abs(dx)+Math.abs(dy)>3)drag.moved=true;world.rotation.y+=dx*.005;world.rotation.x=Math.max(-.45,Math.min(.45,world.rotation.x+dy*.003));drag.x=event.clientX;drag.y=event.clientY;});
 renderer.domElement.addEventListener("pointerup",event=>{if(!drag)return;if(!drag.moved){const rect=renderer.domElement.getBoundingClientRect();pointer.x=((event.clientX-rect.left)/rect.width)*2-1;pointer.y=-((event.clientY-rect.top)/rect.height)*2+1;raycaster.setFromCamera(pointer,camera);const hit=raycaster.intersectObjects([...visual.nodeObjects.values()].map(x=>x.mesh))[0];if(hit)selectNode(hit.object.userData.nodeId,visual.graph,visual);}drag=null;});
 renderer.domElement.addEventListener("wheel",event=>{event.preventDefault();const direction=camera.position.clone().sub(world.position).normalize();const distance=camera.position.distanceTo(world.position);const next=Math.max(12,Math.min(34,distance+event.deltaY*.015));camera.position.copy(world.position).add(direction.multiplyScalar(next));},{passive:false});
 global.addEventListener("resize",()=>{const width=host.clientWidth,height=host.clientHeight;camera.aspect=width/height;camera.updateProjectionMatrix();renderer.setSize(width,height);});
 byId("render-status").textContent="WebGL ready";
 const clock=new THREE.Clock();
 function animate(){const elapsed=clock.getElapsedTime();if(visual.motion)world.rotation.y+=.0016;for(const edge of visual.edgeObjects){for(const particle of edge.particles){const t=(elapsed*particle.speed+particle.offset)%1;particle.mesh.position.copy(edge.curve.getPoint(t));particle.mesh.visible=edge.active;}}
  for(const item of visual.nodeObjects.values()){item.ring.quaternion.copy(camera.quaternion);const vector=item.mesh.position.clone();world.localToWorld(vector);vector.project(camera);const visible=vector.z<1&&vector.z>-1;item.label.hidden=!visual.labels||!visible;if(visible){item.label.style.left=((vector.x*.5+.5)*host.clientWidth)+"px";item.label.style.top=((-vector.y*.5+.5)*host.clientHeight)+"px";}}
  renderer.render(scene,camera);global.requestAnimationFrame(animate);}
  animate();
}
function bindControls(visual){
 const motion=byId("toggle-motion"),labels=byId("toggle-labels");
 function updateMotion(){motion.setAttribute("aria-pressed",String(!visual.motion));motion.textContent=visual.motion?"Pause motion":"Resume motion";}
 function updateLabels(){labels.setAttribute("aria-pressed",String(visual.labels));labels.textContent=visual.labels?"Hide labels":"Show labels";}
 updateMotion();updateLabels();motion.addEventListener("click",()=>{visual.motion=!visual.motion;updateMotion();});labels.addEventListener("click",()=>{visual.labels=!visual.labels;updateLabels();});
 byId("reset-view").addEventListener("click",()=>{if(visual.world){visual.world.rotation.set(0,0,0);visual.camera.position.set(1,7.5,23);visual.camera.lookAt(1,0,0);}});
}
async function start(){
 try{
  const response=await fetch("command-center-data.json?ts="+Date.now(),{cache:"no-store"});if(!response.ok)throw new Error(`HTTP ${response.status}`);const data=await response.json();if(!data.public_safe||data.schema_version!==1)throw new Error("Unexpected public snapshot schema");
  const {graph,visual}=initModel(data);bindControls(visual);
  try{setupScene(visual);}catch(error){byId("webgl-error").hidden=false;byId("webgl-error").textContent="WebGL is unavailable ("+error.message+"). The accessible node list and detail panel remain usable.";byId("render-status").textContent="WebGL unavailable";console.warn("Observatory WebGL unavailable",error);}
 }catch(error){setBadge("overall-status","attention");byId("snapshot-note").textContent="Aggregate snapshot unavailable; topology not rendered.";byId("render-status").textContent="Snapshot unavailable";console.error(error);}
}
global.SecurityObservatory={buildGraph,NODE_DEFS,EDGE_DEFS};
if(typeof module!=="undefined"&&module.exports)module.exports=global.SecurityObservatory;
if(typeof document!=="undefined")document.addEventListener("DOMContentLoaded",start);
})(globalThis);
