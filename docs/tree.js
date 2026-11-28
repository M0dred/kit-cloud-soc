"use strict";
// Native, keyboard-operable disclosures. The comparison contains no source addresses.
async function renderSnapshotDiff(root, snapshot) {
  const state = root.querySelector("[role=status]");
  const tree = root.querySelector(".diff-tree");
  tree.replaceChildren();
  const add = (parent, tag, text) => {
    const node = document.createElement(tag);
    node.textContent = text;
    parent.appendChild(node);
    return node;
  };
  const count = n => Number.isSafeInteger(n) && n >= 0;
  const fmt = n => count(n) ? n.toLocaleString() : "N/A";
  const utc = stamp => {
    if (typeof stamp !== "string" || !/^\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC$/.test(stamp)) return NaN;
    const t = Date.parse(stamp.replace(" UTC", "Z").replace(" ", "T"));
    return Number.isFinite(t) && new Date(t).toISOString().slice(0, 16).replace("T", " ")+" UTC" === stamp ? t : NaN;
  };
  if (snapshot.public_revision) {
    state.textContent = "Comparison unavailable for a display-only correction. No new data batch is implied.";
    return true;
  }
  const groups = [
    ["Telemetry", [
      ["alerts_7d", "Wazuh alerts · rolling 7 days", snapshot.wazuh?.total_7d],
      ["outside_top_500_alerts", "Alerts outside the top-500 buckets · 24h", snapshot.wazuh?.pipeline_24h_coverage?.outside_top_alerts],
    ]],
    ["Catalog and public watchlist", [
      ["misp_ip_attributes", "MISP IP attributes", snapshot.misp?.total],
      ["watchlist", "Public watchlist entries", snapshot.blocklist_n],
    ]],
  ];
  try {
    const response = await fetch("snapshot-diff.json", {cache: "no-store", signal: globalThis.AbortSignal?.timeout?.(12000)});
    if (!response.ok) throw Error("comparison unavailable");
    const diff = await response.json();
    if (diff?.schema_version !== 1 || diff.current_utc !== snapshot.generated || !Number.isFinite(utc(diff.current_utc)))
      throw Error("comparison batch does not match");
    if (diff.previous_utc === null && diff.metrics === null && diff.sources === null) {
      state.textContent = "No previous comparable batch is available. An unavailable comparison does not mean no change.";
      return true;
    }
    if (!(utc(diff.previous_utc) < utc(diff.current_utc))) throw Error("invalid previous batch");
    for (const [, rows] of groups) {
      for (const [key, , current] of rows) {
        const pair = diff.metrics?.[key];
        if (!Array.isArray(pair) || pair.length !== 2 || !pair.every(n => n === null || count(n)) || pair[1] !== current)
          throw Error("inconsistent comparison metrics");
      }
    }
    const s = diff.sources;
    const displayed = snapshot.wazuh?.top_src?.length;
    if (!s || ![s.entered, s.left, s.retained, s.changed_alert_counts].every(n => count(n) && n <= 20) ||
        s.entered+s.retained !== displayed || s.left+s.retained > 20 || s.changed_alert_counts > s.retained)
      throw Error("inconsistent comparison rows");
    state.textContent = `Previous published batch: ${diff.previous_utc} · Displayed batch: ${diff.current_utc}.`;
    const group = (label, open=false) => {
      const branch = add(tree, "details", "");
      branch.open = open;
      add(branch, "summary", label);
      return add(branch, "ul", "");
    };
    function delta(a,b) {
      if (!count(a) || !count(b)) return "change unknown";
      return b > a ? `+${fmt(b-a)}` : b < a ? `−${fmt(a-b)}` : "no change";
    }
    for (const [label, rows] of groups) {
      const list = group(label, label === "Telemetry");
      for (const [key, name] of rows) {
        const [a,b] = diff.metrics[key];
        add(list, "li", `${name}: ${fmt(a)} → ${fmt(b)} (${delta(a,b)})`);
      }
    }
    const rows = group("Public top-20 source set");
    add(rows, "li", `Entered displayed set: ${fmt(s.entered)} · Left displayed set: ${fmt(s.left)}`);
    add(rows, "li", `Retained: ${fmt(s.retained)} · Retained with changed alert count: ${fmt(s.changed_alert_counts)}`);
    add(rows, "li", "These are changes to the ranked, privacy-filtered view; leaving it does not mean a source disappeared or was cleared.");
    return true;
  } catch (_) {
    tree.replaceChildren();
    state.textContent = "No matching batch comparison could be verified. Current snapshot remains available above.";
    return false;
  }
}
