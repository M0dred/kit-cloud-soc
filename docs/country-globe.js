"use strict";
// Orthographic projection of the same validated local Natural Earth geometry.
const GlobeGeometry=(()=>{
  const rad=Math.PI/180;
  const wrap=lon=>((lon+180)%360+360)%360-180;
  const unit=(lon,lat)=>{const a=lon*rad,b=lat*rad,c=Math.cos(b);return [c*Math.cos(a),c*Math.sin(a),Math.sin(b)];};
  const angles=([x,y])=>[x/1.86-17/1.86-180,85-(y-23)/2];
  function camera(lon,lat){
    const a=lon*rad,b=lat*rad,ca=Math.cos(a),sa=Math.sin(a),cb=Math.cos(b),sb=Math.sin(b);
    return ([x,y,z])=>{const t=x*ca+y*sa;return [y*ca-x*sa,z*cb-t*sb,t*cb+z*sb];};
  }
  function limb(a,b){
    const t=a[2]/(a[2]-b[2]),x=a[0]+(b[0]-a[0])*t,y=a[1]+(b[1]-a[1])*t;
    const d=Math.hypot(x,y)||1;return [x/d,y/d,0];
  }
  const coords=p=>p.split(',').map(Number);
  function lines(d){
    return [...d.matchAll(/M([^MZ]+)Z/g)].map(([,line])=>line.split('L').map(p=>unit(...angles(coords(p)))));
  }
  return {wrap,unit,angles,camera,limb,lines};
})();

function createCountryGlobe(onSelect,onVisibility){
  const el=id=>document.getElementById(id), canvas=el('country-globe'), shell=el('globe-stage'), flat=el('flat-map'), toggle=el('globe-toggle');
  if(!canvas||!shell||!flat||!toggle)return null;
  const ctx=canvas.getContext?.('2d');if(!ctx)return null;
  const reduced=globalThis.matchMedia?.('(prefers-reduced-motion: reduce)');
  const visible=()=>!shell.hidden;
  const {wrap,unit,angles,camera,limb,lines}=GlobeGeometry;
  let outline=null,land=[],anchors=new Map(),items=[],mode='alerts',active=null,freshUntil=0;
  let lon=48,lat=21,moved=null,queued=0,hits=[];
  const earthGrid=[];
  for(let a=-150;a<=180;a+=30)earthGrid.push(Array.from({length:37},(_,i)=>unit(a,-90+i*5)));
  for(let b=-60;b<=60;b+=30)earthGrid.push(Array.from({length:73},(_,i)=>unit(-180+i*5,b)));
  const addData=(code,value,group)=>({code,value,group,xyz:anchors.get(code)});
  const metricName=()=>mode==='coverage'?'fresh coverage':mode==='rows'?'source rows':'bucket alerts';
  const request=()=>{if(visible()&&!queued)queued=globalThis.requestAnimationFrame(draw);};
  function draw(){
    queued=0;if(!visible()||!outline)return;
    const box=canvas.getBoundingClientRect();if(box.width<1||box.height<1)return;
    const ratio=Math.min(2,globalThis.devicePixelRatio||1),w=box.width,h=box.height;
    const width=Math.round(w*ratio),height=Math.round(h*ratio);
    if(canvas.width!==width||canvas.height!==height){canvas.width=width;canvas.height=height;}
    ctx.setTransform(ratio,0,0,ratio,0,0);ctx.clearRect(0,0,w,h);
    const cx=w/2,cy=h/2,r=Math.min(w,h)*.435,project=camera(lon,lat);
    function plot(p,move){ctx[move?'moveTo':'lineTo'](cx+p[0]*r,cy-p[1]*r);}
    function strokeLine(points,closed=false){
      let a=project(points[0]);if(a[2]>=0)plot(a,true);
      for(let i=1;i<points.length+(closed?1:0);i++){
        const b=project(points[i%points.length]);
        if(a[2]>=0&&b[2]>=0)plot(b,false);
        else if(a[2]>=0){plot(limb(a,b),false);}
        else if(b[2]>=0){plot(limb(a,b),true);plot(b,false);}
        a=b;
      }
    }
    const sea=ctx.createRadialGradient(cx-r*.28,cy-r*.35,r*.03,cx,cy,r);
    sea.addColorStop(0,'#214561');sea.addColorStop(.8,'#122339');sea.addColorStop(1,'#0c192b');
    ctx.beginPath();ctx.arc(cx,cy,r,0,Math.PI*2);ctx.fillStyle=sea;ctx.fill();
    ctx.save();ctx.clip();
    ctx.beginPath();for(const line of earthGrid)strokeLine(line);ctx.strokeStyle='#3a5b73';ctx.lineWidth=.65;ctx.stroke();
    ctx.beginPath();for(const [,points] of land)strokeLine(points,true);ctx.strokeStyle='#7694a4';ctx.lineWidth=.65;ctx.stroke();
    const picked=items.find(item=>item.code===active),members=new Set(picked?.members||[]);
    ctx.beginPath();for(const [code,points] of land)if(members.has(code))strokeLine(points,true);
    ctx.strokeStyle='#f4d397';ctx.lineWidth=1.35;ctx.stroke();
    const observed=items.flatMap(group=>[...group.native].map(([code,value])=>addData(code,value,group)))
      .filter(x=>x.xyz&&Number.isFinite(x.value)&&x.value>=0).sort((a,b)=>a.value-b.value);
    const max=mode==='coverage'?100:Math.max(1,...observed.map(x=>x.value));
    const now=Date.now(),flash=freshUntil>now&&!reduced?.matches&&!document.hidden;
    hits=[];let label=null;
    for(const data of observed){
      const [x,y,z]=project(data.xyz);if(z<0.025)continue;
      const px=cx+x*r,py=cy-y*r,size=2.7+6*Math.sqrt(data.value/max), selected=data.group.code===active;
      if(flash&&data.value>0){
        const progress=Math.max(0,1-(freshUntil-now)/1400);
        ctx.beginPath();ctx.arc(px,py,size+5+progress*18,0,Math.PI*2);
        ctx.strokeStyle=`rgba(164,244,230,${.8*(1-progress)})`;ctx.lineWidth=1.4;ctx.stroke();
      }
      ctx.beginPath();ctx.arc(px,py,size,0,Math.PI*2);
      ctx.fillStyle=selected?'#f4d397':'#82d9cf';if(data.value>0)ctx.fill();
      ctx.strokeStyle=selected?'#fff0c9':data.value===0?'#a3ccd0':'#133743';ctx.lineWidth=1.2;ctx.stroke();
      hits.push({px,py,size,code:data.group.code});
      if(selected&&(!label||data.value>label.value))label={px,py,value:data.value,text:data.group.label};
    }
    ctx.restore();ctx.beginPath();ctx.arc(cx,cy,r,0,Math.PI*2);ctx.strokeStyle='#648ea1';ctx.lineWidth=1.1;ctx.stroke();
    if(label){
      ctx.font='600 13px system-ui,sans-serif';ctx.textBaseline='bottom';
      const x=Math.max(7,Math.min(w-ctx.measureText(label.text).width-7,label.px+11));
      ctx.strokeStyle='#0b1322';ctx.lineWidth=4;ctx.strokeText(label.text,x,label.py-8);ctx.fillStyle='#fff1d6';ctx.fillText(label.text,x,label.py-8);
    }
    if(flash)request();
  }
  function rotate(dx,dy){lon=wrap(lon+dx);lat=Math.max(-80,Math.min(80,lat+dy));request();}
  function center(){
    const selected=items.find(s=>s.code===active);if(!selected)return;
    const code=selected.native.has(active)&&anchors.has(active)?active:[...selected.native.keys()].find(k=>anchors.has(k))||active;
    if(outline.anchors.has(code)){
      [lon,lat]=angles(outline.anchors.get(code));lat=Math.max(-80,Math.min(80,lat));request();
    }
  }
  el('globe-west').addEventListener('click',()=>rotate(-24,0));el('globe-east').addEventListener('click',()=>rotate(24,0));
  el('globe-up').addEventListener('click',()=>rotate(0,15));el('globe-down').addEventListener('click',()=>rotate(0,-15));
  el('globe-center').addEventListener('click',center);
  toggle.addEventListener('click',()=>{
    if(!outline)return;
    const open=!visible();shell.hidden=!open;flat.hidden=open;toggle.textContent=open?'Use flat map':'3D globe';
    toggle.setAttribute('aria-pressed',String(open));
    onVisibility();if(open)request();
  });
  canvas.addEventListener('pointerdown',e=>{if(e.button!==0||moved)return;moved={id:e.pointerId,x:e.clientX,y:e.clientY,delta:0};canvas.setPointerCapture?.(e.pointerId);});
  canvas.addEventListener('pointermove',e=>{
    if(moved?.id!==e.pointerId)return;const dx=e.clientX-moved.x,dy=e.clientY-moved.y;
    moved.x=e.clientX;moved.y=e.clientY;moved.delta+=Math.abs(dx)+Math.abs(dy);if(moved.delta>3)rotate(-dx*.4,dy*.38);
  });
  canvas.addEventListener('pointerup',e=>{
    if(moved?.id!==e.pointerId)return;const click=moved.delta<4;moved=null;
    if(click){const rect=canvas.getBoundingClientRect(),x=e.clientX-rect.left,y=e.clientY-rect.top;
      const hit=[...hits].reverse().find(p=>Math.hypot(p.px-x,p.py-y)<=p.size+5);if(hit)onSelect(hit.code);}
  });
  canvas.addEventListener('pointercancel',()=>{moved=null;});
  if(typeof ResizeObserver==='function')new ResizeObserver(request).observe(canvas);
  else globalThis.addEventListener?.('resize',request);
  return {visible,setWorld(world){
    outline=world;land=world.land.flatMap(([code,d])=>lines(d).map(line=>[code,line]));
    anchors=new Map([...world.anchors].map(([k,p])=>[k,unit(...angles(p))]));toggle.hidden=false;
    request();
  },update(rows,metric,code,deadline){
    items=rows;mode=metric;active=code;freshUntil=deadline;
    const current=items.find(s=>s.code===active);
    el('globe-center').disabled=!(current&&[active,...current.native.keys()].some(k=>anchors.has(k)));
    el('globe-legend').textContent=`Dots: observed original country labels · size: ${metricName()} · gold outline: selection. Back of globe not shown.`;
    request();
  }};
}
