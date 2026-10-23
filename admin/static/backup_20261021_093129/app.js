"use strict";

const STATE_LABEL = {
  xong: "Xong",
  mot_phan: "Một phần",
  chua_chay: "Chưa chạy",
};

const LOCK_LABEL = {
  leaky: "leaky",
  dqn_h1: "h1",
  dqn_h2: "h2",
  gamma: "γ",
  episodes: "episode",
  max_turn: "max turn",
  dqn_lr: "lr",
  epsilon_start: "ε đầu",
  epsilon_end: "ε cuối",
};

let current = null;
let selected = 0;
let loading = false;

function pct(value) {
  if (typeof value !== "number" || Number.isNaN(value)) return "—";
  return (value * 100).toFixed(1) + "%";
}

function text(id, value) {
  const node = document.getElementById(id);
  if (node) node.textContent = value;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function el(tag, className, content) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (content != null) node.textContent = content;
  return node;
}

function pairClass(row) {
  if (row.state !== "done") return "pending";
  return row.match ? "match" : "miss";
}

function pairWord(row) {
  if (row.state !== "done") return "chưa nộp";
  return row.match ? "khớp" : "lệch";
}

function renderKpis(data) {
  const stages = data.stages || [];
  const done = stages.filter((row) => row.state === "xong").length;
  const partial = stages.filter((row) => row.state === "mot_phan").length;
  const idle = stages.filter((row) => row.state === "chua_chay").length;
  text("kpi-pipeline", done + "/" + stages.length);
  text("kpi-pipeline-sub", partial + " một phần · " + idle + " chưa chạy");

  const cuckoo = data.cuckoo || {};
  text("kpi-cuckoo", (cuckoo.n_match || 0) + "/" + (cuckoo.n_pairs || 0));
  text(
    "kpi-cuckoo-sub",
    (cuckoo.n_pending || 0) + " chưa nộp · " + (cuckoo.n_miss || 0) + " lệch"
  );

  const vt = data.virustotal || {};
  const evasion = vt.evasion || {};
  const paperEvasion = vt.paper_ifm_evasion || {};
  text("kpi-vt", pct(evasion.mean));
  text("kpi-vt-sub", "Paper IF-MalEvade " + pct(paperEvasion.mean));

  const train = data.train || {};
  text("kpi-gan", pct(train.gan_last_evade_batch));
  const turns = typeof train.mean_turns === "number" ? train.mean_turns.toFixed(0) : "—";
  text(
    "kpi-dqn",
    "DQN 20 episode " + pct(train.dqn_evade_last20) + " · eval " + turns + " lượt"
  );
}

function renderStages(stages) {
  const host = document.getElementById("stages");
  clear(host);
  (stages || []).forEach((row) => {
    const card = el("article", "stage " + (row.state || "chua_chay"));
    card.title = row.lab || "";
    const head = el("header");
    head.append(
      el("span", "paper-id", row.paper || ""),
      el("span", "key " + (row.state === "xong" ? "xong" : row.state === "mot_phan" ? "partial" : "idle"), STATE_LABEL[row.state] || row.state)
    );
    card.append(head, el("strong", "", row.title || ""), el("p", "", row.lab || ""));
    host.appendChild(card);
  });
}

function renderCommand(data) {
  const cuckoo = data.cuckoo || {};
  const command = cuckoo.next_command;
  const baselines = data.baselines || {};
  const finished = !command
    && (cuckoo.n_pending || 0) === 0
    && (cuckoo.n_pairs || 0) > 0
    && baselines.mab_vt_status === "done"
    && baselines.malfox_vt_status === "done";
  text(
    "cmd",
    command || (finished ? "Đã đủ kết quả cuối. Không còn lệnh phải chạy." : "Đã có kết quả cho mọi cặp eval.")
  );
  document.getElementById("copy").disabled = !command;
  const smoke = cuckoo.smoke;
  const file = smoke && smoke.file ? String(smoke.file).split(/[/\\]/).pop() : "";
  text(
    "smoke",
    smoke
      ? "Smoke " + (file || "mẫu lành") + " · " + (smoke.state || "—") + " · " + (smoke.analysis_id || "")
      : ""
  );
}

function renderCorpus(corpus) {
  const host = document.getElementById("corpus");
  clear(host);
  const rows = [
    ["Malware", corpus.n_malware, corpus.paper_n_malware],
    ["Benign", corpus.n_benign, corpus.paper_n_benign],
    ["Eval", corpus.eval_n, corpus.paper_eval_n],
    ["Chiều", corpus.n_features, corpus.paper_n_features],
    ["Họ", corpus.family, corpus.paper_family],
  ];
  rows.forEach((row) => {
    const line = el("div", "metric");
    line.append(
      el("p", "metric-name", row[0]),
      el("p", "", "Lab " + (row[1] == null ? "—" : row[1])),
      el("p", "", "Paper " + (row[2] == null ? "—" : row[2]))
    );
    host.appendChild(line);
  });
}

const SHORT = {
  RandomForest: "RF",
  GradientBoosting: "GB",
  MLP: "MLP",
  DecisionTree: "DT",
};

const FULL = {
  RF: "Random Forest",
  GB: "Gradient Boosting",
  MLP: "MLP",
  DT: "Decision Tree",
  IFM: "IF-MalEvade",
  "Gốc": "File gốc",
  MalFox: "MalFox",
  MAB: "MAB-Malware",
};

let chartStamp = "";
let cuckooStamp = "";

const SVG_NS = "http://www.w3.org/2000/svg";

function num(value) {
  return typeof value === "number" && !Number.isNaN(value) ? value : null;
}

function svgEl(name, attrs) {
  const node = document.createElementNS(SVG_NS, name);
  Object.keys(attrs || {}).forEach((key) => node.setAttribute(key, attrs[key]));
  return node;
}

function groupedChart(groups, series, hatchId) {
  const width = 640;
  const height = 292;
  const pad = { l: 40, r: 8, t: 16, b: 44 };
  const innerW = width - pad.l - pad.r;
  const innerH = height - pad.t - pad.b;
  const svg = svgEl("svg", { viewBox: "0 0 " + width + " " + height });
  const defs = svgEl("defs");
  const pattern = svgEl("pattern", {
    id: hatchId,
    width: "6",
    height: "6",
    patternUnits: "userSpaceOnUse",
    patternTransform: "rotate(45)",
  });
  pattern.append(
    svgEl("rect", { width: "6", height: "6", fill: "#e2e8f0" }),
    svgEl("rect", { width: "2", height: "6", fill: "#64748b" })
  );
  defs.appendChild(pattern);
  svg.appendChild(defs);

  function yOf(value) {
    const clamped = Math.max(0, Math.min(1, value));
    return pad.t + innerH - clamped * innerH;
  }

  [0, 0.5, 1].forEach((tick) => {
    const y = yOf(tick);
    svg.appendChild(svgEl("line", {
      x1: pad.l, x2: width - pad.r, y1: y, y2: y, class: "grid",
    }));
    const label = svgEl("text", { x: pad.l - 6, y: y + 4, "text-anchor": "end", class: "axis" });
    label.textContent = String(Math.round(tick * 100));
    svg.appendChild(label);
  });

  const slot = innerW / Math.max(groups.length, 1);
  const spoken = [];
  groups.forEach((group, index) => {
    const center = pad.l + slot * index + slot / 2;
    const barW = Math.min(26, (slot - 20) / series.length);
    const gap = 4;
    const total = series.length * barW + (series.length - 1) * gap;
    let x = center - total / 2;
    const lines = [group.full || FULL[group.name] || group.name];
    series.forEach((spec, seriesIndex) => {
      const value = num(group.values[seriesIndex]);
      spoken.push(group.name + " " + spec.label + " " + pct(value));
      lines.push(spec.label + " " + pct(value));
      const extra = group.details && group.details[seriesIndex];
      if (extra) lines.push(extra);
      if (value != null) {
        const y = yOf(value);
        const attrs = {
          x: x,
          y: y,
          width: barW,
          height: Math.max(0, pad.t + innerH - y),
          rx: 3,
          class: spec.cls + " bar",
        };
        if (spec.cls === "paper-bar") attrs.fill = "url(#" + hatchId + ")";
        const rect = svgEl("rect", attrs);
        rect.style.animationDelay = (index * 70 + seriesIndex * 40) + "ms";
        svg.appendChild(rect);
      }
      x += barW + gap;
    });
    const hit = svgEl("rect", {
      x: pad.l + slot * index,
      y: pad.t,
      width: slot,
      height: innerH,
      class: "hit",
      tabindex: "0",
    });
    hit.dataset.tip = lines.join("\n");
    svg.appendChild(hit);
    const tick = svgEl("text", { x: center, y: height - 16, "text-anchor": "middle", class: "tick" });
    tick.textContent = group.name;
    svg.appendChild(tick);
  });
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", spoken.join(". "));
  return svg;
}

function placeTip(plot, tip, event) {
  const bounds = plot.getBoundingClientRect();
  const tipBox = tip.getBoundingClientRect();
  const pointed = event && typeof event.clientX === "number";
  let x = pointed ? event.clientX - bounds.left + 12 : 16;
  let y = pointed ? event.clientY - bounds.top + 14 : 16;
  if (x + tipBox.width > bounds.width) x = Math.max(8, x - tipBox.width - 24);
  if (y + tipBox.height > bounds.height) y = Math.max(8, y - tipBox.height - 20);
  tip.style.left = x + "px";
  tip.style.top = y + "px";
}

function showTip(plot, tip, hit, event) {
  tip.textContent = hit.dataset.tip || "";
  tip.hidden = false;
  placeTip(plot, tip, event);
}

function chartCard(title, caption, chart) {
  const card = el("article", "card chart");
  const head = el("div", "card-head");
  head.appendChild(el("h3", "", title));
  const plot = el("div", "plot");
  const tip = el("p", "tip");
  tip.hidden = true;
  plot.append(chart, tip);
  chart.querySelectorAll(".hit").forEach((hit) => {
    hit.addEventListener("pointerenter", (event) => showTip(plot, tip, hit, event));
    hit.addEventListener("pointermove", (event) => placeTip(plot, tip, event));
    hit.addEventListener("pointerleave", () => { tip.hidden = true; });
    hit.addEventListener("focus", (event) => showTip(plot, tip, hit, event));
    hit.addEventListener("blur", () => { tip.hidden = true; });
  });
  card.append(head, plot, el("p", "hint", caption));
  return card;
}

function pairCaption(groups, series) {
  return groups.map((group) => {
    const bits = series.map((spec, index) => spec.label + " " + pct(group.values[index]));
    return group.name + " " + bits.join(", ");
  }).join(". ") + ".";
}

function renderTrain(train) {
  const host = document.getElementById("train-stats");
  clear(host);
  const turns = typeof train.mean_turns === "number" ? train.mean_turns.toFixed(1) : "—";
  const rows = [
    ["Né trên eval", pct(train.mutate_evade), "Mẫu RF gọi dưới 0,8"],
    ["MalGAN", pct(train.gan_last_evade_batch), "Batch cuối"],
    ["DQN", pct(train.dqn_evade_last20), "20 episode cuối"],
    ["Số lượt", turns, "Trung bình mỗi mẫu eval"],
  ];
  rows.forEach((row) => {
    const card = el("article", "train-stat");
    card.append(el("h3", "", row[0]), el("p", "kpi-value", row[1]), el("p", "hint", row[2]));
    host.appendChild(card);
  });
}

function rangeLine(span) {
  if (!span || typeof span.min !== "number" || typeof span.max !== "number") return null;
  return "Thấp " + pct(span.min) + " · cao " + pct(span.max);
}

function renderCharts(data) {
  const host = document.getElementById("charts");
  const stamp = JSON.stringify({
    detectors: data.detectors || [],
    virustotal: data.virustotal || {},
    baselines: data.baselines || {},
  });
  if (stamp === chartStamp && host.childElementCount) return;
  chartStamp = stamp;
  clear(host);
  const detectors = data.detectors || [];
  const groupsFor = (pick) => detectors.map((row) => ({
    name: SHORT[row.key] || row.label || row.key,
    full: row.label || row.key,
    values: pick(row.lab || {}, row.paper || {}),
  }));
  const two = [
    { label: "Lab", cls: "lab-bar" },
    { label: "Paper", cls: "paper-bar" },
  ];
  const auc = groupsFor((lab, paper) => [lab.auc, paper.auc]);
  const odr = groupsFor((lab, paper) => [lab.odr, paper.odr]);
  const adr = groupsFor((lab, paper) => [lab.adr, paper.adr]);
  const afterGroups = groupsFor((lab, paper) => [lab.adr, lab.adr_after, paper.adr_after]);
  const afterSeries = [
    { label: "Trước", cls: "before-bar" },
    { label: "Sau", cls: "lab-bar" },
    { label: "Paper", cls: "paper-bar" },
  ];
  host.append(
    chartCard("Table 4 · AUC", pairCaption(auc, two), groupedChart(auc, two, "hatch-auc")),
    chartCard("Table 4 · ODR", pairCaption(odr, two), groupedChart(odr, two, "hatch-odr")),
    chartCard("Table 4 · ADR", pairCaption(adr, two), groupedChart(adr, two, "hatch-adr")),
    chartCard(
      "Table 5 · ADR sau retrain",
      pairCaption(afterGroups, afterSeries),
      groupedChart(afterGroups, afterSeries, "hatch-after")
    )
  );

  const vt = data.virustotal || {};
  const base = data.baselines || {};
  const foxDet = (base.malfox_vt_detection || {}).mean;
  const mabDet = (base.mab_vt_detection || {}).mean;
  const foxEv = (base.malfox_vt_evasion || {}).mean;
  const mabEv = (base.mab_vt_evasion || {}).mean;
  const detGroups = [
    {
      name: "Gốc",
      values: [num((vt.original || {}).mean), num((vt.paper_original || {}).mean)],
      details: [rangeLine(vt.original), rangeLine(vt.paper_original)],
    },
    {
      name: "IFM",
      values: [num((vt.adversarial || {}).mean), num((vt.paper_ifm_detection || {}).mean)],
      details: [rangeLine(vt.adversarial), rangeLine(vt.paper_ifm_detection)],
    },
    {
      name: "MalFox",
      values: [num(foxDet), num(vt.paper_malfoax_detection)],
      details: [rangeLine(base.malfox_vt_detection), null],
    },
    {
      name: "MAB",
      values: [num(mabDet), num(vt.paper_mab_detection)],
      details: [rangeLine(base.mab_vt_detection), null],
    },
  ];
  const evGroups = [
    {
      name: "IFM",
      values: [num((vt.evasion || {}).mean), num((vt.paper_ifm_evasion || {}).mean)],
      details: [rangeLine(vt.evasion), rangeLine(vt.paper_ifm_evasion)],
    },
    {
      name: "MalFox",
      values: [num(foxEv), num(vt.paper_malfoax_evasion)],
      details: [rangeLine(base.malfox_vt_evasion), null],
    },
    {
      name: "MAB",
      values: [num(mabEv), num(vt.paper_mab_evasion)],
      details: [rangeLine(base.mab_vt_evasion), null],
    },
  ];
  const detCard = chartCard(
    "Table 6 · Phát hiện VirusTotal",
    "IFM là IF-MalEvade. " + pairCaption(detGroups, two),
    groupedChart(detGroups, two, "hatch-det")
  );
  const evCard = chartCard(
    "Table 7 · Evasion VirusTotal",
    pairCaption(evGroups, two),
    groupedChart(evGroups, two, "hatch-ev")
  );
  detCard.classList.add("chart-wide");
  evCard.classList.add("chart-wide");
  host.append(detCard, evCard);
}

function renderCuckooSummary(cuckoo) {
  const host = document.getElementById("cuckoo-summary");
  if (!host) return;
  const stamp = JSON.stringify([cuckoo.n_match, cuckoo.n_miss, cuckoo.n_pending, cuckoo.n_pairs]);
  if (stamp === cuckooStamp && host.childElementCount) return;
  cuckooStamp = stamp;
  clear(host);
  const match = cuckoo.n_match || 0;
  const miss = cuckoo.n_miss || 0;
  const pending = cuckoo.n_pending || 0;
  const total = cuckoo.n_pairs || match + miss + pending;
  const bar = el("div", "stack");
  bar.setAttribute("role", "img");
  bar.setAttribute("aria-label", "Khớp " + match + ", lệch " + miss + ", chưa nộp " + pending);
  [
    ["match", match],
    ["miss", miss],
    ["pending", pending],
  ].forEach((part) => {
    if (!part[1]) return;
    const seg = el("span", "seg " + part[0], String(part[1]));
    seg.style.flexGrow = String(part[1]);
    bar.appendChild(seg);
  });
  host.append(
    bar,
    el("p", "hint", match + " khớp · " + miss + " lệch · " + pending + " chưa nộp, trên " + total + " cặp")
  );
}

function renderPairs(pairs) {
  const host = document.getElementById("pair-grid");
  (pairs || []).forEach((row, index) => {
    let button = host.children[index];
    if (!button) {
      button = document.createElement("button");
      button.type = "button";
      button.className = "cell";
      button.addEventListener("click", () => {
        selected = Number(button.dataset.index);
        paintPairState();
        renderDetail();
      });
      host.appendChild(button);
    }
    button.dataset.index = String(row.index);
    button.textContent = String(row.index);
    button.title = row.sha256 || "Chưa có hash";
  });
  while (host.childElementCount > (pairs || []).length) {
    host.removeChild(host.lastElementChild);
  }
  paintPairState();
}

function paintPairState() {
  const pairs = (current && current.cuckoo && current.cuckoo.pairs) || [];
  const host = document.getElementById("pair-grid");
  pairs.forEach((row, index) => {
    const button = host.children[index];
    if (!button) return;
    const kind = pairClass(row);
    const on = row.index === selected;
    button.className = "cell" + (kind === "pending" ? "" : " " + kind) + (on ? " is-on" : "");
    button.setAttribute("aria-pressed", on ? "true" : "false");
    button.setAttribute(
      "aria-label",
      "Cặp " + row.index + ", " + pairWord(row) + (row.sha_prefix ? ", " + row.sha_prefix : "")
    );
  });
}

function sigList(title, names) {
  const block = el("div");
  block.appendChild(el("h3", "", title));
  const list = document.createElement("ul");
  (names || []).forEach((name) => list.appendChild(el("li", "", name)));
  if (!names || !names.length) list.appendChild(el("li", "", "Không có chữ ký"));
  block.appendChild(list);
  return block;
}

function renderDetail() {
  const host = document.getElementById("pair-detail");
  clear(host);
  const pairs = (current && current.cuckoo && current.cuckoo.pairs) || [];
  const row = pairs.find((item) => item.index === selected) || pairs[0];
  if (!row) {
    host.appendChild(el("p", "", "Chưa có danh sách cặp."));
    return;
  }
  host.append(
    el("h3", "", "Cặp " + row.index + " · " + pairWord(row)),
    el("p", "hash", row.sha256 || "Chưa có hash")
  );
  if (row.state !== "done") {
    host.appendChild(el("p", "hint", "Chưa có file kết quả cho cặp này."));
    return;
  }
  host.appendChild(
    el(
      "p",
      "hint",
      "Gốc " + (row.orig_state || "—") + " " + (row.orig_analysis_id || "")
      + " · Adversarial " + (row.adv_state || "—") + " " + (row.adv_analysis_id || "")
    )
  );
  const sigs = el("div", "sigs");
  sigs.append(
    sigList("Chữ ký gốc", row.orig_signatures),
    sigList("Chữ ký adversarial", row.adv_signatures)
  );
  host.appendChild(sigs);
}

function spanText(span) {
  if (!span || typeof span.mean !== "number") return "—";
  const min = typeof span.min === "number" ? pct(span.min) : "—";
  const max = typeof span.max === "number" ? pct(span.max) : "—";
  return pct(span.mean) + " (" + min + "–" + max + ")";
}

function renderBaselines(data) {
  const host = document.getElementById("baselines");
  clear(host);
  const b = data.baselines || {};
  const vt = data.virustotal || {};
  const rows = [
    {
      name: "MalFox",
      state: b.malfoax,
      local: b.malfox_evade,
      det: b.malfox_vt_detection,
      ev: b.malfox_vt_evasion,
      pairs: b.malfox_vt_pairs,
      target: b.malfox_vt_target,
      paperDet: vt.paper_malfoax_detection,
      paperEv: vt.paper_malfoax_evasion,
    },
    {
      name: "MAB-Malware",
      state: b.mab,
      local: b.mab_evade,
      det: b.mab_vt_detection,
      ev: b.mab_vt_evasion,
      pairs: b.mab_vt_pairs,
      target: b.mab_vt_target,
      paperDet: vt.paper_mab_detection,
      paperEv: vt.paper_mab_evasion,
    },
  ];
  rows.forEach((row) => {
    const line = el("div", "base");
    const left = el("div");
    const n = row.pairs != null ? row.pairs : 0;
    const target = row.target != null ? row.target : 50;
    left.append(
      el("strong", "", row.name),
      el("p", "hint", "Detector cục bộ " + (STATE_LABEL[row.state] || "Chưa chạy") + " · né GB " + pct(row.local))
    );
    const right = el("div");
    right.append(
      el("p", "hint", "Lab VT phát hiện " + spanText(row.det) + " · evasion " + spanText(row.ev) + " · " + n + "/" + target),
      el("p", "hint", "Paper phát hiện " + pct(row.paperDet) + " · evasion " + pct(row.paperEv))
    );
    line.append(left, right);
    host.appendChild(line);
  });
  if (b.note) host.appendChild(el("p", "hint", b.note));
}

function renderLocked(locked) {
  const host = document.getElementById("locked");
  clear(host);
  Object.keys(LOCK_LABEL).forEach((key) => {
    const value = locked && locked[key] != null ? locked[key] : "—";
    host.appendChild(el("span", "lock", LOCK_LABEL[key] + " " + value));
  });
}

function render(data) {
  current = data;
  const corpus = data.corpus || {};
  text("preset", (data.preset || "lab_dataset") + " · " + (data.source || ""));
  const api = data.cuckoo_api || {};
  const pill = document.getElementById("api-pill");
  const online = api.status === "online";
  pill.dataset.state = online ? "online" : "offline";
  pill.textContent = online ? "Cuckoo online" : "Cuckoo offline";
  text("updated", data.generated_at ? "Cập nhật " + data.generated_at.replace("T", " ") : "Chưa có mốc thời gian");
  renderKpis(data);
  renderStages(data.stages);
  renderCommand(data);
  renderCorpus(corpus);
  renderTrain(data.train || {});
  renderCharts(data);
  renderCuckooSummary(data.cuckoo || {});
  renderPairs((data.cuckoo || {}).pairs || []);
  renderDetail();
  renderBaselines(data);
  renderLocked((data.train || {}).locked);
}

async function load() {
  if (loading) return;
  loading = true;
  const button = document.getElementById("refresh");
  button.setAttribute("aria-busy", "true");
  const banner = document.getElementById("banner");
  try {
    const response = await fetch("/api/status", { cache: "no-store" });
    if (!response.ok) throw new Error("HTTP " + response.status);
    const data = await response.json();
    banner.hidden = true;
    render(data);
  } catch (error) {
    banner.hidden = false;
    banner.textContent = "Chưa đọc được /api/status. " + error.message;
  } finally {
    loading = false;
    button.removeAttribute("aria-busy");
  }
}

async function copyCommand() {
  const command = current && current.cuckoo && current.cuckoo.next_command;
  const note = document.getElementById("copy-note");
  if (!command) {
    note.textContent = "Không có lệnh để chép.";
    return;
  }
  try {
    await navigator.clipboard.writeText(command);
  } catch (error) {
    const area = document.createElement("textarea");
    area.value = command;
    document.body.appendChild(area);
    area.select();
    document.execCommand("copy");
    area.remove();
  }
  note.textContent = "Đã chép lệnh.";
}

document.getElementById("refresh").addEventListener("click", load);
document.getElementById("copy").addEventListener("click", copyCommand);
load();
setInterval(load, 20000);
