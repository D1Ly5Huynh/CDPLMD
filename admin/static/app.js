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
  text("cmd", command || "Đã có kết quả cho mọi cặp eval.");
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

function addBar(host, name, lab, paper) {
  const row = el("div", "bar-row");
  const labW = typeof lab === "number" ? Math.max(0, Math.min(1, lab)) : 0;
  const paperW = typeof paper === "number" ? Math.max(0, Math.min(1, paper)) : 0;
  const tracks = el("div", "tracks");
  const labTrack = el("div", "track");
  const paperTrack = el("div", "track paper");
  const labBar = document.createElement("i");
  const paperBar = document.createElement("i");
  labBar.style.setProperty("--w", String(labW));
  paperBar.style.setProperty("--w", String(paperW));
  labTrack.appendChild(labBar);
  paperTrack.appendChild(paperBar);
  tracks.append(labTrack, paperTrack);
  tracks.setAttribute(
    "role",
    "img"
  );
  tracks.setAttribute(
    "aria-label",
    name + ". Lab " + pct(lab) + ". Paper " + pct(paper) + "."
  );
  row.append(el("span", "bar-name", name), tracks, el("span", "bar-val", pct(lab) + " · " + pct(paper)));
  host.appendChild(row);
}

function renderDetectors(detectors) {
  const host = document.getElementById("detectors");
  clear(host);
  const after = [];
  (detectors || []).forEach((row) => {
    const lab = row.lab || {};
    const paper = row.paper || {};
    addBar(host, row.label || row.key, lab.adr, paper.adr);
    after.push((row.label || row.key) + " " + pct(lab.adr_after));
  });
  text("adr-after", "ADR sau retrain, lab: " + after.join(", ") + ".");
}

function renderVt(vt) {
  const host = document.getElementById("vt-chart");
  clear(host);
  const original = vt.original || {};
  const adversarial = vt.adversarial || {};
  const evasion = vt.evasion || {};
  const paperOriginal = vt.paper_original || {};
  const paperDetect = vt.paper_ifm_detection || {};
  const paperEvasion = vt.paper_ifm_evasion || {};
  addBar(host, "Phát hiện gốc", original.mean, paperOriginal.mean);
  addBar(host, "Phát hiện adversarial", adversarial.mean, paperDetect.mean);
  addBar(host, "Evasion", evasion.mean, paperEvasion.mean);
  text("vt-note", vt.note || "");
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
  text("preset", (data.preset || "dike2500") + " · " + (data.source || ""));
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
  renderDetectors(data.detectors);
  renderVt(data.virustotal || {});
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
