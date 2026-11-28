'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const dir=path.join(__dirname,'../docs');
const read=name=>fs.readFileSync(path.join(dir,name),'utf8');
const markup=read('command-center.html');
const script=read('command-center.js');
const data=JSON.parse(read('command-center-data.json'));
const ids=[...markup.matchAll(/\bid="([^"]+)"/g)].map(([,v])=>v);
assert.equal(ids.length,new Set(ids).size);
assert.match(markup,/connect-src 'self'/);
assert.doesNotMatch(markup,/unsafe-inline/);
assert.doesNotMatch(script,/innerHTML/);
for(const id of script.matchAll(/byId\("([^"]+)"\)/g))assert(ids.includes(id[1]),`missing DOM id ${id[1]}`);
assert.equal(data.schema_version,1);
assert.equal(data.public_safe,true);
assert.equal(data.cluster.nodes_total,data.cluster.nodes_ready);
assert.equal(data.cluster.pods_total,data.cluster.pods_ready);
for(const value of [data.rag.embedding_coverage_pct,data.rag.asset_coverage_pct,data.ai.success_rate_pct,data.ai.gateway_error_rate_pct,data.security_logs.top_signature_share_pct]){
 assert(Number.isFinite(value)&&value>=0&&value<=100,`invalid percentage ${value}`);
}
const publicText=markup+'\n'+script+'\n'+JSON.stringify(data);
assert.doesNotMatch(publicText,/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
assert.doesNotMatch(publicText,/\b(?:kit-lab|debian)\b/i);
assert.doesNotMatch(publicText,/gho_[A-Za-z0-9]+|Pwdn0|ELASTIC_PASSWORD=/i);
assert.match(read('index.html'),/href="command-center\.html">Command center/);
console.log('Command center: strict CSP, DOM ids, aggregate ranges and public privacy checks passed');
