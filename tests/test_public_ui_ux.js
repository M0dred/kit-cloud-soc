// Extra public UI checks using only the committed, privacy-gated snapshot and synthetic status.
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..');
const page = fs.readFileSync(path.join(root, 'docs/index.html'), 'utf8');
const script = fs.readFileSync(path.join(root, 'docs/app.js'), 'utf8');
const fixture = JSON.parse(fs.readFileSync(path.join(root, 'docs/data.json'), 'utf8'));
const ids = [...page.matchAll(/\bid="([^"]+)"/g)].map(x => x[1]);
const timestamp = Date.parse(fixture.generated.replace(' UTC', 'Z').replace(' ', 'T'));

class Element {
  constructor() { this.children = []; this.listeners = {}; this.style = {}; this.hidden = false; this.value = ''; this._text = ''; }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(''); }
  set innerHTML(_) { throw Error('Unsafe dynamic HTML'); }
  appendChild(child) { this.children.push(child); return child; }
  replaceChildren(...children) { this._text = ''; this.children = children; }
  setAttribute(name, value) { this[name] = value; }
  addEventListener(name, fn) { this.listeners[name] = fn; }
}
async function render(data, report, now = timestamp + 3600000) {
  const elements = Object.fromEntries(ids.map(id => [id, new Element()]));
  const document = {getElementById(id) { assert(elements[id], `Missing ${id}`); return elements[id]; },
    createElement() { return new Element(); }};
  const FixedDate = class extends Date { static now() { return now; } };
  const fetch = async url => ({ok: true, json: async () => url === 'status.json' ? report : data});
  vm.runInNewContext(script, {document, Date: FixedDate, fetch, console}, {timeout: 2000});
  await new Promise(resolve => setTimeout(resolve, 10));
  return elements;
}
(async () => {
  assert(page.includes('href="#main-content"'), 'Keyboard skip-to-content link required');
  assert(page.includes('id="main-content" class="container" tabindex="-1"'), 'Skip link must have a focus target');
  assert(page.includes('id="snapshot-note"'), 'Snapshot interpretation banner required');
  assert(page.includes('id="source-scope" aria-live="polite"'), 'Filter result count must be announced');
  const healthy = {schema_version: 1, state: 'ok', last_attempt_utc: fixture.generated};
  const e = await render(fixture, healthy);
  assert.match(e['snapshot-note'].textContent, /latest published batch snapshot/i);
  assert.match(e['snapshot-note'].textContent, /not live/i);
  const first = fixture.wazuh.top_src[0][0];
  const button = e.src.children[1].children[0].children[0].children[0];
  button.listeners.click();
  assert.equal(e['ioc-detail'].hidden, false);
  const filter = e['source-filter'];
  filter.value = first.replace(/\.(?=[^.]+$)/, '[.]');
  filter.listeners.input();
  assert.match(e['source-scope'].textContent, /^1 of /, 'Defanged pasted IP should match');
  filter.value = 'no-matching-public-source';
  filter.listeners.input();
  assert.equal(e['ioc-detail'].hidden, true, 'Old source detail must not survive filtering');
  assert.match(e['source-scope'].textContent, /no sources match/i);
  assert.match(e.src.children[1].textContent, /no sources match/i);

  const missing = structuredClone(fixture);
  missing.wazuh.total_7d = null; missing.misp.total = null;
  missing.vt.posted_total = null; missing.blocklist_n = null;
  const unknown = await render(missing, healthy);
  assert.deepEqual(Array.from(unknown.kpis.children, c => c.children[1].textContent),
    ['N/A', 'N/A', 'N/A', 'N/A'], 'Unknown metrics must not be displayed as zero');
  const missingDays = structuredClone(fixture);
  missingDays.wazuh.by_day = [];
  missingDays.wazuh.pipeline_24h_coverage.approx_source_values = null;
  missingDays.wazuh.pipeline_24h_coverage.outside_top_alerts = 2;
  const incomplete = await render(missingDays, healthy);
  assert.match(incomplete['day-values'].textContent, /daily values unavailable/i);
  assert.match(incomplete['pipeline-coverage'].textContent, /an unknown number of source values/i);
  assert(!incomplete['pipeline-coverage'].textContent.includes('approximately 0 source values'));
  const missingBucket = structuredClone(fixture);
  missingBucket.wazuh.by_day = [["2026-10-29", null]];
  const bucket = await render(missingBucket, healthy);
  assert.match(bucket['day-values'].textContent, /2026-10-29: N\/A/);
  assert.equal(bucket.days.children.length, 0, 'Unknown bucket volume must not render a zero-height bar');
  const noSources = structuredClone(fixture);
  noSources.wazuh.top_src = []; noSources.wazuh.source_context = {};
  noSources.misp.top_source_membership = {};
  const empty = await render(noSources, healthy);
  assert.match(empty['source-scope'].textContent, /no displayed source rows/i);
  assert.match(empty.src.children[1].textContent, /no displayed source rows/i);
  assert(!empty['source-scope'].textContent.includes('0 alerts'));

  const degraded = await render(fixture, {...healthy, state: 'degraded'});
  assert.match(degraded['snapshot-note'].textContent, /previous safe snapshot/i);
  assert.equal(degraded['status-pill'].textContent, 'PIPELINE DEGRADED');
  const stale = await render(fixture, healthy, timestamp + 49 * 3600000);
  assert.match(stale['snapshot-note'].textContent, /older than 24h/i);
  assert.equal(stale['status-pill'].textContent, 'STALE SNAPSHOT');
  const later = new Date(timestamp + 3600000).toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
  const lag = await render(fixture, {...healthy, last_attempt_utc: later}, timestamp + 2 * 3600000);
  assert.match(lag['snapshot-note'].textContent, /newer than displayed data/i);
  assert.equal(lag['status-pill'].textContent, 'SNAPSHOT LAGS RUN');
  const earlier = new Date(timestamp - 3600000).toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
  const mismatch = await render(fixture, {...healthy, last_attempt_utc: earlier});
  assert.equal(mismatch['status-pill'].textContent, 'STATUS MISMATCH');
  const unknownStatus = await render(fixture, {schema_version: 1, state: 'unknown', last_attempt_utc: fixture.generated});
  assert.equal(unknownStatus['status-pill'].textContent, 'STATUS UNKNOWN');
  const unavailable = await render(null, healthy);
  assert.equal(unavailable['status-pill'].textContent, 'UNAVAILABLE');
  assert.match(unavailable['snapshot-note'].textContent, /no counts or source conclusions/i);
  assert.equal(unavailable.kpis.children.length, 0);
  console.log('Public UI scope, honesty, filtering and freshness checks OK');
})().catch(e => { console.error(e); process.exitCode = 1; });
