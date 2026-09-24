"use strict";

/* ============================================================
   ACT-NOW publication state of play
   Static front end. Data is encrypted in the browser with a key
   derived from the passcode and stored as one blob via /api/data.
   ============================================================ */

const STAGES = [
  { id: "in_dev", label: "In development", short: "In dev", pre: true },
  { id: "being_updated", label: "Being updated", short: "Being updated", pre: true },
  { id: "in_tech_review", label: "In technical review", short: "In tech review", pre: true, split: true },
  { id: "completed_tech_review", label: "Technical review complete", short: "Tech review complete", pre: true, split: true },
  { id: "awaiting_publication", label: "Awaiting publication", short: "Awaiting publication", pre: true, split: true },
  { id: "published", label: "Published / current", short: "Published / current" },
  { id: "superseded", label: "Superseded", short: "Superseded" },
  { id: "discontinued", label: "Discontinued", short: "Discontinued" },
];
const PRE = STAGES.filter((s) => s.pre);
const POST = STAGES.filter((s) => !s.pre);
const SPLIT = STAGES.filter((s) => s.split).map((s) => s.id);
const stageLabel = Object.fromEntries(STAGES.map((s) => [s.id, s.label]));

const PBKDF2_ITER = 310000;
const TOKEN_SALT = "actnow-publication-state-site-token-v1";
const LOG_MAX = 500;
const IDLE_LOCK_MS = 30 * 60 * 1000;

/* ---------- state ---------- */
let DATA = null;       // decrypted data
let VERSION = 0;       // server version
let KEY = null;        // CryptoKey
let SALT = null;       // Uint8Array, salt for KEY
let TOKEN = "";        // site token sent to the function
let FIRST_RUN = false;

const view = {
  tab: "play",
  asAt: null,          // null means latest
  compare: "prev",     // "prev" | "none" | snapshot id
  editing: false,
  editBase: null,      // snapshot id being edited
  draft: null,         // rows being edited
  showAllTr: false,
  trendStream: "all",
};

/* ---------- small helpers ---------- */
const $ = (s, el = document) => el.querySelector(s);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const clone = (o) => JSON.parse(JSON.stringify(o));
const uid = (p) => p + "-" + Math.random().toString(36).slice(2, 9) + Date.now().toString(36).slice(-4);
const int = (v) => { const n = parseInt(v, 10); return Number.isFinite(n) && n > 0 ? n : 0; };

function todayISO() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}
function fmtDate(iso) {
  if (!iso) return "";
  const [y, m, d] = iso.slice(0, 10).split("-");
  return `${d}/${m}/${y}`;
}
function fmtDateTime(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  return d.toLocaleString("en-NZ", { day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit" });
}
function dayNum(iso) { return Date.UTC(+iso.slice(0, 4), +iso.slice(5, 7) - 1, +iso.slice(8, 10)) / 86400000; }

function toast(msg, ms = 3200) {
  const t = $("#toast");
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => (t.hidden = true), ms);
}

function deviceName() {
  try {
    let n = localStorage.getItem("pub-device");
    if (!n) {
      const ua = navigator.userAgent;
      n = /iPhone|iPad/.test(ua) ? "iOS device" : /Android/.test(ua) ? "Android device" : /Mac/.test(ua) ? "Mac" : /Windows/.test(ua) ? "Windows PC" : /CrOS/.test(ua) ? "Chromebook" : "Browser";
      localStorage.setItem("pub-device", n);
    }
    return n;
  } catch { return "Browser"; }
}

/* ---------- crypto ---------- */
const enc = new TextEncoder();
const dec = new TextDecoder();
const b64 = (buf) => { let s = ""; const b = new Uint8Array(buf); for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return btoa(s); };
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

async function pbkdf2Bits(pass, salt, bits) {
  const base = await crypto.subtle.importKey("raw", enc.encode(pass), "PBKDF2", false, ["deriveBits"]);
  return crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: PBKDF2_ITER, hash: "SHA-256" }, base, bits);
}
async function deriveKey(pass, salt) {
  const bits = await pbkdf2Bits(pass, salt, 256);
  return crypto.subtle.importKey("raw", bits, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}
async function siteToken(pass) {
  const bits = await pbkdf2Bits(pass, enc.encode(TOKEN_SALT), 256);
  return Array.from(new Uint8Array(bits), (b) => b.toString(16).padStart(2, "0")).join("");
}
async function encryptData(obj, key, salt) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(JSON.stringify(obj)));
  return { salt: b64(salt), iv: b64(iv), cipher: b64(cipher) };
}
async function decryptRecord(rec, key) {
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(rec.iv) }, key, unb64(rec.cipher));
  return JSON.parse(dec.decode(plain));
}

/* ---------- API ---------- */
async function apiGet(token = TOKEN) {
  const r = await fetch("/api/data", { headers: { "x-site-token": token }, cache: "no-store" });
  if (r.status === 401) throw Object.assign(new Error("token"), { code: 401 });
  if (!r.ok) throw new Error("Could not reach the site storage (" + r.status + ").");
  return r.json();
}
async function apiPut(payload, baseVersion) {
  const r = await fetch("/api/data", {
    method: "PUT",
    headers: { "content-type": "application/json", "x-site-token": TOKEN },
    body: JSON.stringify({ ...payload, baseVersion, device: deviceName() }),
  });
  const body = await r.json().catch(() => ({}));
  if (r.status === 409) throw Object.assign(new Error("conflict"), { code: 409 });
  if (r.status === 401) throw Object.assign(new Error("The site no longer accepts this passcode. Check PUBLICATION_TOKEN in Netlify."), { code: 401 });
  if (!r.ok) throw new Error(body.error || "Save failed (" + r.status + ").");
  return body;
}

function setSync(text) { $("#syncState").textContent = text; }

/* Apply a change to the data and store it. On a version conflict, reload the
   latest copy, re-apply the same change and try once more. */
async function commit(mutate, logText) {
  const attempt = async (base) => {
    const next = clone(base);
    const text = mutate(next);
    const line = typeof text === "string" && text ? text : logText;
    if (line) {
      next.changeLog = next.changeLog || [];
      next.changeLog.unshift({ at: new Date().toISOString(), device: deviceName(), text: line });
      next.changeLog = next.changeLog.slice(0, LOG_MAX);
    }
    const payload = await encryptData(next, KEY, SALT);
    const res = await apiPut(payload, VERSION);
    DATA = next;
    VERSION = res.version;
    setSync("Saved " + fmtDateTime(res.updatedAt));
  };
  setSync("Saving...");
  try {
    await attempt(DATA);
  } catch (e) {
    if (e.code !== 409) { setSync("Not saved"); throw e; }
    const rec = await apiGet();
    DATA = await decryptRecord(rec, KEY);
    VERSION = rec.version;
    await attempt(DATA);
    toast("Another device had saved first. Your change was applied on top of it.");
  }
}

/* ---------- data helpers ---------- */
function emptyRow() {
  const counts = Object.fromEntries(STAGES.map((s) => [s.id, 0]));
  const updates = Object.fromEntries(SPLIT.map((id) => [id, 0]));
  const byReviewer = Object.fromEntries((DATA?.reviewers || []).map((r) => [r.id, 0]));
  return { counts, updates, note: "", tr: { one: 0, none: 0, byReviewer } };
}
function normRow(row) {
  const r = emptyRow();
  if (!row) return r;
  for (const s of STAGES) r.counts[s.id] = int(row.counts?.[s.id]);
  for (const id of SPLIT) r.updates[id] = int(row.updates?.[id]);
  r.note = row.note || "";
  r.tr.one = int(row.tr?.one);
  r.tr.none = int(row.tr?.none);
  for (const [k, v] of Object.entries(row.tr?.byReviewer || {})) r.tr.byReviewer[k] = int(v);
  return r;
}
function sortedSnaps() {
  return [...DATA.snapshots].sort((a, b) => (a.asAt < b.asAt ? -1 : a.asAt > b.asAt ? 1 : (a.recordedAt < b.recordedAt ? -1 : 1)));
}
function latestSnap() { const s = sortedSnaps(); return s[s.length - 1] || null; }
function snapAt(dateISO) {
  let found = null;
  for (const s of sortedSnaps()) if (s.asAt <= dateISO) found = s;
  return found;
}
function viewedSnap() { return view.asAt ? snapAt(view.asAt) : latestSnap(); }
function prevSnap(snap) {
  const s = sortedSnaps();
  const i = s.findIndex((x) => x.id === snap.id);
  return i > 0 ? s[i - 1] : null;
}
function compareSnap(snap) {
  if (!snap || view.compare === "none") return null;
  if (view.compare === "prev") return prevSnap(snap);
  const c = DATA.snapshots.find((s) => s.id === view.compare);
  return c && c.id !== snap.id ? c : null;
}
function rowsOf(snap) {
  return view.editing && snap && snap.id === view.editBase ? view.draft : (snap?.rows || {});
}
function streamById(id) { return DATA.streams.find((s) => s.id === id); }

/* Streams to show: active ones, plus retired ones holding figures in these rows. */
function visibleStreams(rows) {
  return DATA.streams.filter((s) => {
    if (s.active) return true;
    const r = rows[s.id];
    if (!r) return false;
    return STAGES.some((st) => int(r.counts?.[st.id]) > 0) || int(r.tr?.one) + int(r.tr?.none) > 0;
  });
}

function newCount(row, stageId) {
  const c = int(row.counts?.[stageId]);
  if (stageId === "in_dev") return c;
  if (stageId === "being_updated") return 0;
  if (SPLIT.includes(stageId)) return Math.max(0, c - int(row.updates?.[stageId]));
  return c;
}
function updCount(row, stageId) {
  if (stageId === "being_updated") return int(row.counts?.[stageId]);
  if (SPLIT.includes(stageId)) return Math.min(int(row.counts?.[stageId]), int(row.updates?.[stageId]));
  return 0;
}

/* The summary figures, following the spreadsheet's own formulas. */
function metrics(rows, ids) {
  const list = (ids || Object.keys(rows)).map((id) => normRow(rows[id]));
  const t = Object.fromEntries(STAGES.map((s) => [s.id, 0]));
  const n = Object.fromEntries(STAGES.map((s) => [s.id, 0]));
  const u = Object.fromEntries(STAGES.map((s) => [s.id, 0]));
  for (const r of list) for (const s of STAGES) { t[s.id] += r.counts[s.id]; n[s.id] += newCount(r, s.id); u[s.id] += updCount(r, s.id); }
  const newPre = PRE.reduce((a, s) => a + n[s.id], 0);
  const updPre = PRE.reduce((a, s) => a + u[s.id], 0);
  return {
    totals: t, news: n, upds: u,
    authored: newPre + t.superseded + t.discontinued + t.published,
    published: t.published,
    discSup: t.superseded + t.discontinued,
    newPre, updPre,
    passed: t.published + t.discontinued + t.superseded + n.in_tech_review + n.completed_tech_review + n.awaiting_publication,
  };
}

function rowWarnings(row) {
  const r = normRow(row);
  const w = [];
  for (const id of SPLIT) {
    if (r.updates[id] > r.counts[id]) w.push(`Updates in ${stageLabel[id].toLowerCase()} (${r.updates[id]}) exceed the count (${r.counts[id]})`);
  }
  const trSum = r.tr.one + r.tr.none;
  if (trSum !== r.counts.in_tech_review) w.push(`Technical review breakdown (${trSum}) does not match in technical review (${r.counts.in_tech_review})`);
  const expected = r.tr.one + 2 * r.tr.none;
  const byRev = Object.values(r.tr.byReviewer).reduce((a, b) => a + int(b), 0);
  if (byRev !== expected) w.push(`Outstanding reviews by reviewer (${byRev}) do not match the expected ${expected}`);
  return w;
}

/* ---------- gate ---------- */
async function initGate() {
  $("#seedDate").value = todayISO();
  try {
    const probe = await apiGet("");
    if (probe.empty) showFirstRun();
  } catch (e) {
    // 401 here just means a token is configured, so the site already has data.
  }
  $("#pass").focus();
}
function showFirstRun() {
  FIRST_RUN = true;
  $("#firstRun").hidden = false;
  $("#gateBtn").textContent = "Set passcode and load spreadsheet figures";
}

$("#gateForm").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const pass = $("#pass").value;
  const msg = $("#gateMsg");
  const btn = $("#gateBtn");
  msg.textContent = "";
  if (pass.length < 8) { msg.textContent = "Use at least 8 characters."; return; }
  btn.disabled = true;
  btn.textContent = "Working...";
  try {
    TOKEN = await siteToken(pass);
    let rec;
    try { rec = await apiGet(); }
    catch (e) { if (e.code === 401) throw new Error("That passcode is not accepted by this site."); throw e; }

    if (rec.empty) {
      if (!FIRST_RUN) { showFirstRun(); throw new Error("This site has no data yet. Confirm the passcode to set it up."); }
      if (pass !== $("#pass2").value) throw new Error("The two passcodes do not match.");
      const seedDate = $("#seedDate").value;
      if (!seedDate) throw new Error("Enter the date the spreadsheet figures reflect.");
      const seed = await (await fetch("seed.json", { cache: "no-store" })).json();
      seed.snapshots.forEach((s) => { if (!s.asAt) s.asAt = seedDate; });
      SALT = crypto.getRandomValues(new Uint8Array(16));
      KEY = await deriveKey(pass, SALT);
      DATA = seed;
      VERSION = 0;
      await commit(() => `Loaded the spreadsheet figures as the snapshot for ${fmtDate(seedDate)}`);
    } else {
      SALT = unb64(rec.salt);
      KEY = await deriveKey(pass, SALT);
      try { DATA = await decryptRecord(rec, KEY); }
      catch { throw new Error("Passcode incorrect."); }
      VERSION = rec.version;
      setSync("Loaded " + fmtDateTime(rec.updatedAt));
      if (!rec.tokenRequired) setTimeout(() => toast("Storage is not yet locked to the passcode. See Settings, Security."), 800);
    }
    $("#pass").value = "";
    $("#pass2").value = "";
    $("#gate").hidden = true;
    $("#app").hidden = false;
    armIdle();
    render();
  } catch (e) {
    msg.textContent = e.message || String(e);
    KEY = null; DATA = null;
  } finally {
    btn.disabled = false;
    btn.textContent = FIRST_RUN ? "Set passcode and load spreadsheet figures" : "Unlock";
  }
});

function lock() {
  if (view.editing && draftChanges().length && !confirm("Discard unsaved changes and lock?")) return;
  DATA = null; KEY = null; SALT = null; TOKEN = ""; VERSION = 0;
  view.editing = false; view.draft = null; view.editBase = null;
  view.asAt = null; view.compare = "prev"; view.tab = "play";
  $("#app").hidden = true;
  $("#gate").hidden = false;
  $("#gateMsg").textContent = "";
  $("#pass").focus();
}
let idleTimer;
function armIdle() {
  clearTimeout(idleTimer);
  idleTimer = setTimeout(() => { if (KEY && !(view.editing && draftChanges().length)) { lock(); $("#gateMsg").textContent = "Locked after 30 minutes without activity."; } }, IDLE_LOCK_MS);
}
["click", "keydown"].forEach((ev) => document.addEventListener(ev, () => { if (KEY) armIdle(); }));

/* ---------- editing ---------- */
function startEdit(snap) {
  const base = snap || latestSnap();
  view.editing = true;
  view.editBase = base.id;
  view.draft = {};
  for (const s of visibleStreams(base.rows)) view.draft[s.id] = normRow(base.rows[s.id]);
  render();
}
function draftChanges() {
  if (!view.editing) return [];
  const base = DATA.snapshots.find((s) => s.id === view.editBase);
  return diffRows(base?.rows || {}, view.draft);
}
function diffRows(a, b) {
  const out = [];
  for (const s of DATA.streams) {
    const ra = normRow(a[s.id]); const rb = normRow(b[s.id]);
    const parts = [];
    for (const st of STAGES) if (ra.counts[st.id] !== rb.counts[st.id]) parts.push(`${st.label.toLowerCase()} ${ra.counts[st.id]} to ${rb.counts[st.id]}`);
    for (const id of SPLIT) if (ra.updates[id] !== rb.updates[id]) parts.push(`updates in ${stageLabel[id].toLowerCase()} ${ra.updates[id]} to ${rb.updates[id]}`);
    if (ra.tr.one !== rb.tr.one) parts.push(`approved by one TR ${ra.tr.one} to ${rb.tr.one}`);
    if (ra.tr.none !== rb.tr.none) parts.push(`approved by no TRs ${ra.tr.none} to ${rb.tr.none}`);
    for (const rv of DATA.reviewers) {
      const x = int(ra.tr.byReviewer[rv.id]); const y = int(rb.tr.byReviewer[rv.id]);
      if (x !== y) parts.push(`${rv.name} outstanding ${x} to ${y}`);
    }
    if ((ra.note || "") !== (rb.note || "")) parts.push("note changed");
    if (parts.length) out.push(`${s.name}: ${parts.join(", ")}`);
  }
  return out;
}
function endEdit() { view.editing = false; view.draft = null; view.editBase = null; }

function saveDialog() {
  const changes = draftChanges();
  const base = DATA.snapshots.find((s) => s.id === view.editBase);
  const isLatest = base.id === latestSnap().id;
  const defDate = isLatest && !view.asAt ? todayISO() : base.asAt;
  openModal("Save snapshot", `
    <div class="field"><label for="svDate">State of play as at</label><input id="svDate" type="date" value="${esc(defDate)}"></div>
    <p class="small muted" id="svHint"></p>
    <div class="field"><label for="svNote">Note (optional)</label><input id="svNote" type="text" maxlength="200" placeholder="For example, after the Lymphoma technical review batch"></div>
    <div class="small"><strong>${changes.length ? changes.length + " stream" + (changes.length === 1 ? "" : "s") + " changed" : "No figures changed"}</strong></div>
    ${changes.length ? `<div class="changes">${changes.map((c) => `<div>${esc(c)}</div>`).join("")}</div>` : ""}
    <div class="modal-actions"><button class="btn ghost" data-action="close-modal">Cancel</button><button class="btn primary" id="svGo">Save snapshot</button></div>`);
  const hint = () => {
    const d = $("#svDate").value;
    const existing = DATA.snapshots.find((s) => s.asAt === d);
    const later = DATA.snapshots.some((s) => s.asAt > d);
    let t = existing ? `This replaces the figures already recorded for ${fmtDate(d)}.` : `This adds a new snapshot for ${fmtDate(d)}.`;
    if (later) t += " Later snapshots are not changed.";
    $("#svHint").textContent = t;
  };
  $("#svDate").addEventListener("input", hint);
  hint();
  $("#svGo").addEventListener("click", async () => {
    const d = $("#svDate").value;
    if (!d) { toast("Choose a date."); return; }
    const note = $("#svNote").value.trim();
    const warnCount = Object.values(view.draft).filter((r) => rowWarnings(r).length).length;
    if (warnCount && !confirm(`${warnCount} stream${warnCount === 1 ? " has" : "s have"} figures that do not reconcile. Save anyway?`)) return;
    const rows = clone(view.draft);
    $("#svGo").disabled = true;
    try {
      await commit((data) => {
        let snap = data.snapshots.find((s) => s.asAt === d);
        const before = snap ? snap.rows : ([...data.snapshots].filter((s) => s.asAt < d).sort((a, b) => (a.asAt < b.asAt ? -1 : 1)).pop()?.rows || {});
        const diffs = diffRows(before, rows);
        if (snap) {
          snap.rows = rows;
          snap.updatedAt = new Date().toISOString();
          snap.device = deviceName();
          if (note) snap.note = note;
        } else {
          snap = { id: uid("snap"), asAt: d, recordedAt: new Date().toISOString(), device: deviceName(), note, rows };
          data.snapshots.push(snap);
        }
        return `Saved snapshot for ${fmtDate(d)}${diffs.length ? ": " + diffs.join("; ") : " (no figures changed)"}`;
      });
      closeModal();
      endEdit();
      view.asAt = latestSnap().asAt === d ? null : d;
      render();
      toast("Snapshot saved for " + fmtDate(d) + ".");
    } catch (e) {
      $("#svGo").disabled = false;
      toast(e.message);
    }
  });
}

/* ---------- modal ---------- */
function openModal(title, html) {
  $("#modalTitle").textContent = title;
  $("#modalBody").innerHTML = html;
  $("#modal").hidden = false;
  const f = $("#modalBody input, #modalBody select, #modalBody textarea, #modalBody button");
  if (f) f.focus();
}
function closeModal() { $("#modal").hidden = true; $("#modalBody").innerHTML = ""; }
$("#modal").addEventListener("click", (e) => { if (e.target.id === "modal") closeModal(); });
document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !$("#modal").hidden) closeModal(); });

/* ---------- render ---------- */
function render() {
  if (!DATA) return;
  const snap = viewedSnap();
  const cmp = compareSnap(snap);
  renderTimeline(snap, cmp);
  renderCompareSel(snap);
  $("#asAtInput").value = view.asAt || snap?.asAt || "";
  const banner = $("#viewBanner");
  if (view.asAt && snap) {
    const latest = latestSnap();
    const isLatest = snap.id === latest.id;
    banner.hidden = isLatest && view.asAt >= latest.asAt;
    banner.innerHTML = `Showing the state of play as at ${fmtDate(view.asAt)}, from the snapshot recorded for ${fmtDate(snap.asAt)}. <button class="linkish" data-action="go-latest">Return to latest</button>`;
  } else if (view.asAt && !snap) {
    banner.hidden = false;
    banner.innerHTML = `No snapshot exists on or before ${fmtDate(view.asAt)}. The earliest is ${fmtDate(sortedSnaps()[0]?.asAt)}. <button class="linkish" data-action="go-latest">Return to latest</button>`;
  } else banner.hidden = true;

  document.querySelectorAll(".tabs button").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.tab === view.tab)));

  const eb = $("#editBar");
  eb.hidden = !view.editing;
  if (view.editing) {
    const base = DATA.snapshots.find((s) => s.id === view.editBase);
    const n = draftChanges().length;
    $("#editMsg").textContent = `Editing figures, starting from the snapshot for ${fmtDate(base.asAt)}. ${n ? n + " stream" + (n === 1 ? "" : "s") + " changed." : "No changes yet."}`;
  }

  const main = $("#main");
  if (view.tab === "play") main.innerHTML = renderPlay(snap, cmp);
  else if (view.tab === "tr") main.innerHTML = renderTr(snap, cmp);
  else if (view.tab === "trends") main.innerHTML = renderTrends();
  else if (view.tab === "snapshots") main.innerHTML = renderSnapshots();
  else main.innerHTML = renderSettings();
}

function renderTimeline(snap, cmp) {
  const el = $("#timeline");
  const s = sortedSnaps();
  if (!s.length) { el.innerHTML = ""; return; }
  const a = dayNum(s[0].asAt); const b = dayNum(s[s.length - 1].asAt);
  const pos = (iso) => (s.length === 1 || a === b ? 50 : ((dayNum(iso) - a) / (b - a)) * 100);
  let html = `<div class="track"></div>`;
  if (snap && cmp) {
    const x = pos(cmp.asAt), y = pos(snap.asAt);
    html += `<div class="span" style="left:${Math.min(x, y)}%;width:${Math.abs(y - x)}%"></div>`;
  }
  for (const x of s) {
    const cls = ["dot", snap && x.id === snap.id ? "on" : "", cmp && x.id === cmp.id ? "cmp" : ""].join(" ");
    html += `<button class="${cls}" style="left:${pos(x.asAt)}%" data-action="view-snap" data-id="${esc(x.id)}" title="${esc(fmtDate(x.asAt) + (x.note ? ": " + x.note : ""))}" aria-label="Snapshot ${esc(fmtDate(x.asAt))}"></button>`;
  }
  if (s.length === 1) html += `<span class="tick" style="left:50%">${fmtDate(s[0].asAt)}</span>`;
  else {
    html += `<span class="tick left" style="left:0">${fmtDate(s[0].asAt)}</span><span class="tick right" style="left:100%">${fmtDate(s[s.length - 1].asAt)}</span>`;
    if (snap && snap.id !== s[0].id && snap.id !== s[s.length - 1].id) {
      const p = pos(snap.asAt);
      if (p > 14 && p < 86) html += `<span class="tick" style="left:${p}%;font-weight:700;opacity:1">${fmtDate(snap.asAt)}</span>`;
    }
  }
  el.innerHTML = html;
}

function renderCompareSel(snap) {
  const sel = $("#compareSel");
  const opts = [`<option value="prev">Previous snapshot</option>`, `<option value="none">Do not compare</option>`];
  for (const x of sortedSnaps().reverse()) {
    if (snap && x.id === snap.id) continue;
    opts.push(`<option value="${esc(x.id)}">${fmtDate(x.asAt)}${x.note ? " (" + esc(x.note.slice(0, 40)) + ")" : ""}</option>`);
  }
  sel.innerHTML = opts.join("");
  sel.value = [...sel.options].some((o) => o.value === view.compare) ? view.compare : "prev";
}

function deltaHtml(now, then, show) {
  if (!show) return "";
  const d = now - then;
  if (!d) return "";
  return `<span class="delta ${d > 0 ? "up" : "down"}">${d > 0 ? "+" : "\u2212"}${Math.abs(d)}</span>`;
}

function renderPlay(snap, cmp) {
  if (!snap) return `<div class="empty">No snapshot exists for this date. Choose a later date or return to the latest.</div>`;
  const rows = rowsOf(snap);
  const cmpRows = cmp ? cmp.rows : null;
  const streams = visibleStreams(rows);
  const ids = streams.map((s) => s.id);
  const m = metrics(rows, ids);
  const mc = cmpRows ? metrics(cmpRows, Object.keys(cmpRows)) : null;
  const show = !!mc && !view.editing;
  const editing = view.editing && snap.id === view.editBase;

  const stageBox = (s) => `<div class="stage" style="--c:var(--s-${s.id})">
      <div class="n">${m.totals[s.id]}${deltaHtml(m.totals[s.id], mc?.totals[s.id] ?? 0, show)}</div>
      <div class="l">${esc(s.label)}</div>
      ${s.split && m.upds[s.id] ? `<div class="sub">${m.upds[s.id]} update${m.upds[s.id] === 1 ? "" : "s"}</div>` : ""}
    </div>`;
  const pipeline = `<div class="pipeline" aria-label="Totals by stage">
    <div class="pipe-group flow">${PRE.map(stageBox).join("")}</div>
    <div class="pipe-group">${POST.map(stageBox).join("")}</div></div>`;

  const metric = (n, now, then, l) => `<div class="metric"><div class="n">${now}${deltaHtml(now, then ?? 0, show)}</div><div class="l">${l}</div></div>`;
  const summary = `<div class="summary">
    ${metric("authored", m.authored, mc?.authored, "Total regimens authored")}
    ${metric("published", m.published, mc?.published, "Published / current")}
    ${metric("discSup", m.discSup, mc?.discSup, "Discontinued or superseded")}
    ${metric("newPre", m.newPre, mc?.newPre, "New regimens in pre-publication")}
    ${metric("updPre", m.updPre, mc?.updPre, "Updates in pre-publication")}
    ${metric("passed", m.passed, mc?.passed, "Passed authoring")}
  </div>
  <details class="defs"><summary>How these figures are calculated</summary><dl>
    <dt>Total regimens authored</dt><dd>New regimens in pre-publication, plus published, superseded and discontinued. Updates to published regimens are left out because the regimen is already counted as published.</dd>
    <dt>New regimens in pre-publication</dt><dd>Everything in development, plus regimens in technical review, review complete or awaiting publication that have never been published. The spreadsheet labelled this "In prepublication".</dd>
    <dt>Updates in pre-publication</dt><dd>Everything being updated, plus the updates recorded against the three review and publication stages.</dd>
    <dt>Passed authoring</dt><dd>Published, superseded and discontinued, plus new regimens in technical review, review complete or awaiting publication.</dd>
  </dl></details>`;

  const warns = streams.map((s) => ({ s, w: rowWarnings(rows[s.id]) })).filter((x) => x.w.length);
  const warnHtml = warns.length ? `<div class="warnings"><strong>${warns.length} stream${warns.length === 1 ? " does" : "s do"} not reconcile</strong><ul>${warns.map((x) => `<li>${esc(x.s.name)}: ${x.w.map(esc).join("; ")}</li>`).join("")}</ul></div>` : "";

  const head = `<tr><th>Tumour stream</th>${STAGES.map((s, i) => `<th class="${i === PRE.length ? "group" : ""}"><span class="sw" style="--c:var(--s-${s.id})"></span>${esc(s.short)}</th>`).join("")}<th style="text-align:left">Note</th></tr>`;
  const body = streams.map((st) => {
    const r = normRow(rows[st.id]);
    const c = cmpRows ? normRow(cmpRows[st.id]) : null;
    const w = rowWarnings(r);
    const cells = STAGES.map((s, i) => {
      const cls = i === PRE.length ? "group" : "";
      if (editing) {
        const baseSnap = DATA.snapshots.find((x) => x.id === view.editBase);
        const orig = normRow(baseSnap.rows[st.id]);
        const ch = orig.counts[s.id] !== r.counts[s.id] ? " changed" : "";
        let h = `<input class="num${ch}" type="number" min="0" step="1" inputmode="numeric" value="${r.counts[s.id]}" data-edit="count" data-stream="${esc(st.id)}" data-stage="${s.id}" aria-label="${esc(st.name + ", " + s.label)}">`;
        if (s.split) {
          const chu = orig.updates[s.id] !== r.updates[s.id] ? " changed" : "";
          h += `<span class="upd-label">of which updates</span><input class="num upd-in${chu}" type="number" min="0" step="1" inputmode="numeric" value="${r.updates[s.id]}" data-edit="update" data-stream="${esc(st.id)}" data-stage="${s.id}" aria-label="${esc(st.name + ", " + s.label + ", of which updates")}">`;
        }
        return `<td class="${cls}">${h}</td>`;
      }
      const v = r.counts[s.id];
      const u = s.split && r.updates[s.id] ? `<span class="upd">${r.updates[s.id]} upd</span>` : "";
      return `<td class="${cls}${v ? "" : " zero"}">${v}${u}${deltaHtml(v, c ? c.counts[s.id] : 0, show && !!c)}</td>`;
    }).join("");
    const note = editing ? `<input class="txt" type="text" maxlength="200" value="${esc(r.note)}" data-edit="note" data-stream="${esc(st.id)}" aria-label="${esc(st.name + " note")}">` : esc(r.note);
    return `<tr class="${st.active ? "" : "retired"}"><td>${esc(st.name)}${st.active ? "" : " (retired)"}${w.length ? `<span class="flag" title="${esc(w.join("\n"))}">!</span>` : ""}</td>${cells}<td class="note">${note}</td></tr>`;
  }).join("");
  const foot = `<tr><td>Total</td>${STAGES.map((s, i) => `<td class="${i === PRE.length ? "group" : ""}">${m.totals[s.id]}${deltaHtml(m.totals[s.id], mc?.totals[s.id] ?? 0, show)}</td>`).join("")}<td></td></tr>
    <tr class="sub"><td>Not previously published</td>${STAGES.map((s, i) => `<td class="${i === PRE.length ? "group" : ""}">${s.pre ? m.news[s.id] : ""}</td>`).join("")}<td></td></tr>`;

  const snapInfo = `<p class="small muted">Snapshot for ${fmtDate(snap.asAt)}, recorded ${fmtDateTime(snap.updatedAt || snap.recordedAt)}${snap.device ? " on " + esc(snap.device) : ""}.${snap.note ? " " + esc(snap.note) + (/[.!?]$/.test(snap.note) ? "" : ".") : ""}${cmp && !view.editing ? ` Changes shown are since ${fmtDate(cmp.asAt)}.` : ""}</p>`;

  const isLatest = snap.id === latestSnap().id;
  const tools = view.editing ? "" : `<div class="toolbar">
      ${isLatest ? `<button class="btn primary" data-action="edit">Update figures</button>` : `<button class="btn" data-action="edit-this">Correct this snapshot</button>`}
      <span class="spacer"></span>
      <button class="btn ghost" data-action="csv">Download CSV</button>
      <button class="btn ghost" data-action="print">Print</button>
    </div>`;

  return `${pipeline}${summary}${tools}${snapInfo}${warnHtml}<div class="table-wrap"><table><thead>${head}</thead><tbody>${body}</tbody><tfoot>${foot}</tfoot></table></div>`;
}

function renderTr(snap, cmp) {
  if (!snap) return `<div class="empty">No snapshot exists for this date.</div>`;
  const rows = rowsOf(snap);
  const editing = view.editing && snap.id === view.editBase;
  const show = !!cmp && !view.editing;
  const cmpRows = cmp?.rows;
  const revs = DATA.reviewers.filter((r) => r.active || Object.values(rows).some((row) => int(row?.tr?.byReviewer?.[r.id]) > 0));
  let streams = visibleStreams(rows);
  if (!editing && !view.showAllTr) {
    streams = streams.filter((s) => { const r = normRow(rows[s.id]); return r.counts.in_tech_review || r.tr.one || r.tr.none || Object.values(r.tr.byReviewer).some(Boolean); });
  }
  const tot = { itr: 0, one: 0, none: 0, exp: 0, rev: Object.fromEntries(revs.map((r) => [r.id, 0])) };
  const cell = (st, key, val, label) => editing
    ? `<input class="num" type="number" min="0" step="1" inputmode="numeric" value="${val}" data-edit="${key}" data-stream="${esc(st.id)}" aria-label="${esc(st.name + ", " + label)}">`
    : String(val);
  const body = streams.map((st) => {
    const r = normRow(rows[st.id]);
    const c = cmpRows ? normRow(cmpRows[st.id]) : null;
    const exp = r.tr.one + 2 * r.tr.none;
    const byRev = revs.reduce((a, rv) => a + int(r.tr.byReviewer[rv.id]), 0);
    tot.itr += r.counts.in_tech_review; tot.one += r.tr.one; tot.none += r.tr.none; tot.exp += exp;
    revs.forEach((rv) => (tot.rev[rv.id] += int(r.tr.byReviewer[rv.id])));
    const ok = r.tr.one + r.tr.none === r.counts.in_tech_review && byRev === exp;
    return `<tr><td>${esc(st.name)}</td>
      <td>${r.counts.in_tech_review}${deltaHtml(r.counts.in_tech_review, c?.counts.in_tech_review ?? 0, show && !!c)}</td>
      <td>${cell(st, "tr-one", r.tr.one, "approved by one TR")}</td>
      <td>${cell(st, "tr-none", r.tr.none, "approved by no TRs")}</td>
      <td class="group">${exp}</td>
      ${revs.map((rv) => `<td>${editing ? `<input class="num" type="number" min="0" step="1" inputmode="numeric" value="${int(r.tr.byReviewer[rv.id])}" data-edit="tr-rev" data-rev="${esc(rv.id)}" data-stream="${esc(st.id)}" aria-label="${esc(st.name + ", " + rv.name)}">` : int(r.tr.byReviewer[rv.id])}</td>`).join("")}
      <td>${byRev}</td>
      <td class="${ok ? "" : "warn-cell"}" style="text-align:left">${ok ? "Reconciles" : "Check"}</td></tr>`;
  }).join("");
  const revTot = revs.reduce((a, rv) => a + tot.rev[rv.id], 0);
  return `<h2>Technical review</h2>
    <p class="muted small">Each regimen needs two technical reviews. Outstanding reviews are one for each regimen approved by one reviewer and two for each approved by none, and should equal the total held by the reviewers. The in technical review count comes from the state of play table.</p>
    <div class="toolbar">
      ${view.editing ? "" : `<label class="small"><input type="checkbox" data-action="toggle-all-tr" ${view.showAllTr ? "checked" : ""}> Show streams with nothing in review</label>`}
      <span class="spacer"></span>
      ${view.editing ? "" : snap.id === latestSnap().id ? `<button class="btn primary" data-action="edit">Update figures</button>` : `<button class="btn" data-action="edit-this">Correct this snapshot</button>`}
    </div>
    ${streams.length ? `<div class="table-wrap"><table>
      <thead><tr><th>Tumour stream</th><th>In technical review</th><th>Approved by one TR</th><th>Approved by no TRs</th><th class="group">Outstanding reviews</th>${revs.map((rv) => `<th>${esc(rv.name)}</th>`).join("")}<th>Held by reviewers</th><th style="text-align:left">Status</th></tr></thead>
      <tbody>${body}</tbody>
      <tfoot><tr><td>Total</td><td>${tot.itr}</td><td>${tot.one}</td><td>${tot.none}</td><td class="group">${tot.exp}</td>${revs.map((rv) => `<td>${tot.rev[rv.id]}</td>`).join("")}<td>${revTot}</td><td></td></tr></tfoot>
    </table></div>` : `<div class="empty">Nothing is in technical review in this snapshot.</div>`}`;
}

/* ---------- trends ---------- */
function renderTrends() {
  const s = sortedSnaps();
  const opts = [`<option value="all">All streams</option>`].concat(DATA.streams.map((x) => `<option value="${esc(x.id)}" ${view.trendStream === x.id ? "selected" : ""}>${esc(x.name)}</option>`));
  const head = `<h2>Trends</h2><div class="toolbar"><label for="trendSel" class="small">Tumour stream</label><select id="trendSel" data-action="trend-stream">${opts.join("")}</select></div>`;
  if (s.length < 2) return head + `<div class="empty">Trends appear once there are two or more snapshots. Save a snapshot after the next change to start the line.</div>`;
  const pick = (snap) => {
    if (view.trendStream === "all") return metrics(snap.rows, Object.keys(snap.rows));
    return metrics({ [view.trendStream]: snap.rows[view.trendStream] || {} }, [view.trendStream]);
  };
  const series = s.map((snap) => ({ d: snap.asAt, m: pick(snap) }));
  const charts = [
    ...STAGES.map((st) => ({ label: st.label, color: `var(--s-${st.id})`, vals: series.map((x) => x.m.totals[st.id]) })),
    { label: "New regimens in pre-publication", color: "var(--navy)", vals: series.map((x) => x.m.newPre) },
    { label: "Total regimens authored", color: "var(--navy)", vals: series.map((x) => x.m.authored) },
  ];
  const x0 = dayNum(series[0].d), x1 = dayNum(series[series.length - 1].d);
  const W = 300, H = 120, L = 30, R = 8, T = 10, B = 22;
  const svg = (c) => {
    let lo = Math.min(...c.vals), hi = Math.max(...c.vals);
    if (lo === hi) { lo = Math.max(0, lo - 1); hi = hi + 1; }
    const px = (d) => L + ((dayNum(d) - x0) / (x1 - x0 || 1)) * (W - L - R);
    const py = (v) => T + (1 - (v - lo) / (hi - lo)) * (H - T - B);
    const pts = series.map((x, i) => `${px(x.d).toFixed(1)},${py(c.vals[i]).toFixed(1)}`);
    return `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(c.label)} over time">
      <line x1="${L}" y1="${H - B}" x2="${W - R}" y2="${H - B}" stroke="#D6DEE7"/>
      <text x="${L - 4}" y="${py(hi) + 4}" font-size="10" text-anchor="end" fill="#5A6878">${hi}</text>
      <text x="${L - 4}" y="${py(lo) + 4}" font-size="10" text-anchor="end" fill="#5A6878">${lo}</text>
      <text x="${L}" y="${H - 6}" font-size="10" fill="#5A6878">${fmtDate(series[0].d)}</text>
      <text x="${W - R}" y="${H - 6}" font-size="10" text-anchor="end" fill="#5A6878">${fmtDate(series[series.length - 1].d)}</text>
      <polyline points="${pts.join(" ")}" fill="none" stroke="${c.color}" stroke-width="2.2"/>
      ${series.map((x, i) => `<circle cx="${px(x.d).toFixed(1)}" cy="${py(c.vals[i]).toFixed(1)}" r="3" fill="${c.color}"><title>${fmtDate(x.d)}: ${c.vals[i]}</title></circle>`).join("")}
    </svg>`;
  };
  return head + `<div class="charts">${charts.map((c) => {
    const now = c.vals[c.vals.length - 1], first = c.vals[0];
    return `<div class="chart"><h4>${esc(c.label)} <span>${now}${deltaHtml(now, first, true)}</span></h4>${svg(c)}</div>`;
  }).join("")}</div><p class="small muted">Each chart has its own scale. The change shown is since the first snapshot.</p>`;
}

/* ---------- snapshots ---------- */
function renderSnapshots() {
  const s = sortedSnaps().reverse();
  const rowsHtml = s.map((x) => {
    const m = metrics(x.rows, Object.keys(x.rows));
    return `<tr><td>${fmtDate(x.asAt)}</td>
      <td style="text-align:left" class="small">${fmtDateTime(x.updatedAt || x.recordedAt)}<br><span class="muted">${esc(x.device || "")}</span></td>
      <td style="text-align:left">${esc(x.note || "")}</td>
      <td>${m.authored}</td><td>${m.published}</td><td>${m.newPre}</td><td>${m.updPre}</td>
      <td style="text-align:left;white-space:nowrap">
        <button class="btn small" data-action="view-snap" data-id="${esc(x.id)}">View</button>
        <button class="btn small ghost" data-action="snap-edit-meta" data-id="${esc(x.id)}">Date and note</button>
        <button class="btn small danger" data-action="snap-delete" data-id="${esc(x.id)}">Delete</button>
      </td></tr>`;
  }).join("");
  return `<h2>Snapshots</h2>
    <p class="muted small">One snapshot is kept per date. Saving again on the same date replaces that date's figures. To see the state of play on any day, pick the date at the top of the page; the app shows the most recent snapshot on or before it.</p>
    <div class="table-wrap"><table><thead><tr><th>As at</th><th style="text-align:left">Recorded</th><th style="text-align:left">Note</th><th>Authored</th><th>Published</th><th>New in pre-pub</th><th>Updates in pre-pub</th><th style="text-align:left">Actions</th></tr></thead><tbody>${rowsHtml}</tbody></table></div>`;
}

/* ---------- settings ---------- */
function renderSettings() {
  const streams = DATA.streams.map((s, i) => `<div class="list-row ${s.active ? "" : "off"}">
      <span class="name">${esc(s.name)}</span>
      <button class="btn small ghost" data-action="stream-up" data-id="${esc(s.id)}" ${i === 0 ? "disabled" : ""} aria-label="Move ${esc(s.name)} up">Up</button>
      <button class="btn small ghost" data-action="stream-down" data-id="${esc(s.id)}" ${i === DATA.streams.length - 1 ? "disabled" : ""} aria-label="Move ${esc(s.name)} down">Down</button>
      <button class="btn small ghost" data-action="stream-rename" data-id="${esc(s.id)}">Rename</button>
      <button class="btn small ${s.active ? "danger" : ""}" data-action="stream-toggle" data-id="${esc(s.id)}">${s.active ? "Retire" : "Restore"}</button>
    </div>`).join("");
  const revs = DATA.reviewers.map((r) => `<div class="list-row ${r.active ? "" : "off"}">
      <span class="name">${esc(r.name)}</span>
      <button class="btn small ghost" data-action="rev-rename" data-id="${esc(r.id)}">Rename</button>
      <button class="btn small ${r.active ? "danger" : ""}" data-action="rev-toggle" data-id="${esc(r.id)}">${r.active ? "Retire" : "Restore"}</button>
    </div>`).join("");
  const log = (DATA.changeLog || []).map((l) => `<div><time>${fmtDateTime(l.at)}</time>${esc(l.text)}${l.device ? ` <span class="muted small">(${esc(l.device)})</span>` : ""}</div>`).join("") || `<div class="muted">No changes recorded yet.</div>`;
  return `<h2>Settings</h2>
  <div class="panel"><h3>Tumour streams</h3>
    <p class="small muted">Renaming a stream renames it throughout the history. Retiring a stream keeps its past figures; it drops out of the table once it holds no regimens.</p>
    ${streams}
    <div class="inline" style="margin-top:.75rem"><input id="newStream" type="text" placeholder="New tumour stream" maxlength="60"><button class="btn" data-action="stream-add">Add stream</button></div>
  </div>
  <div class="panel"><h3>Technical reviewers</h3>${revs}
    <div class="inline" style="margin-top:.75rem"><input id="newRev" type="text" placeholder="Reviewer name" maxlength="60"><button class="btn" data-action="rev-add">Add reviewer</button></div>
  </div>
  <div class="panel"><h3>Security</h3>
    <p class="small">Site token for this passcode. In Netlify, set the environment variable <strong>PUBLICATION_TOKEN</strong> to this value and redeploy, so the storage endpoint rejects anyone without the passcode.</p>
    <code class="token" id="tokenText">${esc(TOKEN)}</code>
    <div class="inline"><button class="btn small" data-action="copy-token">Copy token</button><button class="btn small" data-action="change-pass">Change passcode</button></div>
    <div class="field" style="margin-top:1rem;max-width:320px"><label for="devName">Name for this device in the change log</label><input id="devName" type="text" maxlength="60" value="${esc(deviceName())}" data-action="device-name"></div>
  </div>
  <div class="panel"><h3>Backup</h3>
    <p class="small muted">The backup is an unencrypted JSON file holding every snapshot. Restoring replaces everything on the site.</p>
    <div class="inline"><button class="btn" data-action="backup">Download backup</button><button class="btn danger" data-action="restore">Restore from backup</button><input id="restoreFile" type="file" accept="application/json,.json" hidden></div>
  </div>
  <div class="panel"><h3>Change log</h3><div class="log">${log}</div></div>`;
}

/* ---------- exports ---------- */
function download(name, text, type) {
  const blob = new Blob([text], { type });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = name;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500);
}
function csvCell(v) { const s = String(v ?? ""); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; }
function exportCsv() {
  const snap = viewedSnap();
  const rows = snap.rows;
  const streams = visibleStreams(rows);
  const m = metrics(rows, streams.map((s) => s.id));
  const revs = DATA.reviewers.filter((r) => r.active);
  const out = [];
  out.push(["State of play as at", fmtDate(snap.asAt)]);
  out.push([]);
  out.push(["Tumour stream", ...STAGES.map((s) => s.label), ...SPLIT.map((id) => "Updates in " + stageLabel[id].toLowerCase()), "Note"]);
  for (const st of streams) {
    const r = normRow(rows[st.id]);
    out.push([st.name, ...STAGES.map((s) => r.counts[s.id]), ...SPLIT.map((id) => r.updates[id]), r.note]);
  }
  out.push(["Total", ...STAGES.map((s) => m.totals[s.id]), ...SPLIT.map((id) => m.upds[id])]);
  out.push(["Not previously published", ...STAGES.map((s) => (s.pre ? m.news[s.id] : ""))]);
  out.push([]);
  out.push(["Total regimens authored", m.authored]);
  out.push(["Published / current", m.published]);
  out.push(["Discontinued or superseded", m.discSup]);
  out.push(["New regimens in pre-publication", m.newPre]);
  out.push(["Updates in pre-publication", m.updPre]);
  out.push(["Passed authoring", m.passed]);
  out.push([]);
  out.push(["Tumour stream", "In technical review", "Approved by one TR", "Approved by no TRs", "Outstanding reviews", ...revs.map((r) => r.name)]);
  for (const st of streams) {
    const r = normRow(rows[st.id]);
    out.push([st.name, r.counts.in_tech_review, r.tr.one, r.tr.none, r.tr.one + 2 * r.tr.none, ...revs.map((rv) => int(r.tr.byReviewer[rv.id]))]);
  }
  download(`state-of-play-${snap.asAt}.csv`, out.map((r) => r.map(csvCell).join(",")).join("\r\n"), "text/csv");
}

/* ---------- events ---------- */
document.addEventListener("click", async (e) => {
  const t = e.target.closest("[data-action], [data-tab]");
  if (!t || !DATA && t.dataset.action !== "close-modal") return;
  if (t.dataset.tab) { view.tab = t.dataset.tab; render(); return; }
  const a = t.dataset.action;
  const id = t.dataset.id;
  try {
    switch (a) {
      case "lock": lock(); break;
      case "close-modal": closeModal(); break;
      case "go-latest": if (guardEdit()) { view.asAt = null; render(); } break;
      case "view-snap": {
        if (!guardEdit()) break;
        const s = DATA.snapshots.find((x) => x.id === id);
        view.asAt = s.id === latestSnap().id ? null : s.asAt;
        if (view.tab === "snapshots" || view.tab === "settings") view.tab = "play";
        render(); break;
      }
      case "edit": startEdit(latestSnap()); break;
      case "edit-this": startEdit(viewedSnap()); break;
      case "discard":
        if (!draftChanges().length || confirm("Discard your changes?")) { endEdit(); render(); }
        break;
      case "save": saveDialog(); break;
      case "csv": exportCsv(); break;
      case "print": window.print(); break;
      case "toggle-all-tr": view.showAllTr = t.checked; render(); break;
      case "snap-edit-meta": snapMetaDialog(id); break;
      case "snap-delete": {
        const s = DATA.snapshots.find((x) => x.id === id);
        if (DATA.snapshots.length === 1) { toast("The only snapshot cannot be deleted."); break; }
        if (!confirm(`Delete the snapshot for ${fmtDate(s.asAt)}? This cannot be undone except from a backup.`)) break;
        await commit((d) => { d.snapshots = d.snapshots.filter((x) => x.id !== id); }, `Deleted the snapshot for ${fmtDate(s.asAt)}`);
        if (view.compare === id) view.compare = "prev";
        render(); break;
      }
      case "stream-add": {
        const name = $("#newStream").value.trim();
        if (!name) break;
        if (DATA.streams.some((s) => s.name.toLowerCase() === name.toLowerCase())) { toast("That stream already exists."); break; }
        await commit((d) => { d.streams.push({ id: uid("s"), name, active: true }); }, `Added tumour stream ${name}`);
        render(); break;
      }
      case "stream-rename": {
        const s = streamById(id);
        const name = prompt("New name for " + s.name, s.name);
        if (!name || !name.trim() || name.trim() === s.name) break;
        await commit((d) => { d.streams.find((x) => x.id === id).name = name.trim(); }, `Renamed tumour stream ${s.name} to ${name.trim()}`);
        render(); break;
      }
      case "stream-toggle": {
        const s = streamById(id);
        if (s.active) {
          const r = normRow(latestSnap().rows[id]);
          const held = STAGES.reduce((acc, st) => acc + r.counts[st.id], 0);
          if (held && !confirm(`${s.name} holds ${held} regimens in the latest snapshot. A retired stream stays in the table while it holds figures; set them to zero in a later snapshot to drop it. Retire anyway?`)) break;
        }
        await commit((d) => { const x = d.streams.find((y) => y.id === id); x.active = !x.active; }, `${s.active ? "Retired" : "Restored"} tumour stream ${s.name}`);
        render(); break;
      }
      case "stream-up": case "stream-down": {
        await commit((d) => {
          const i = d.streams.findIndex((x) => x.id === id);
          const j = a === "stream-up" ? i - 1 : i + 1;
          if (j < 0 || j >= d.streams.length) return;
          [d.streams[i], d.streams[j]] = [d.streams[j], d.streams[i]];
        }, null);
        render(); break;
      }
      case "rev-add": {
        const name = $("#newRev").value.trim();
        if (!name) break;
        await commit((d) => { d.reviewers.push({ id: uid("r"), name, active: true }); }, `Added technical reviewer ${name}`);
        render(); break;
      }
      case "rev-rename": {
        const r = DATA.reviewers.find((x) => x.id === id);
        const name = prompt("New name for " + r.name, r.name);
        if (!name || !name.trim() || name.trim() === r.name) break;
        await commit((d) => { d.reviewers.find((x) => x.id === id).name = name.trim(); }, `Renamed technical reviewer ${r.name} to ${name.trim()}`);
        render(); break;
      }
      case "rev-toggle": {
        const r = DATA.reviewers.find((x) => x.id === id);
        await commit((d) => { const x = d.reviewers.find((y) => y.id === id); x.active = !x.active; }, `${r.active ? "Retired" : "Restored"} technical reviewer ${r.name}`);
        render(); break;
      }
      case "copy-token":
        await navigator.clipboard.writeText(TOKEN); toast("Token copied."); break;
      case "change-pass": changePassDialog(); break;
      case "backup":
        download(`publication-state-backup-${todayISO()}.json`, JSON.stringify(DATA, null, 1), "application/json"); break;
      case "restore": $("#restoreFile").click(); break;
    }
  } catch (err) {
    toast(err.message || String(err));
  }
});

function guardEdit() {
  if (!view.editing) return true;
  if (draftChanges().length && !confirm("You have unsaved changes. Discard them?")) return false;
  endEdit();
  return true;
}

document.addEventListener("input", (e) => {
  const t = e.target;
  if (!DATA) return;
  if (t.dataset.edit && view.editing) {
    const sid = t.dataset.stream;
    const row = view.draft[sid] || (view.draft[sid] = emptyRow());
    const k = t.dataset.edit;
    if (k === "count") row.counts[t.dataset.stage] = int(t.value);
    else if (k === "update") row.updates[t.dataset.stage] = int(t.value);
    else if (k === "note") row.note = t.value;
    else if (k === "tr-one") row.tr.one = int(t.value);
    else if (k === "tr-none") row.tr.none = int(t.value);
    else if (k === "tr-rev") row.tr.byReviewer[t.dataset.rev] = int(t.value);
    const n = draftChanges().length;
    const base = DATA.snapshots.find((s) => s.id === view.editBase);
    $("#editMsg").textContent = `Editing figures, starting from the snapshot for ${fmtDate(base.asAt)}. ${n ? n + " stream" + (n === 1 ? "" : "s") + " changed." : "No changes yet."}`;
    t.classList.add("changed");
  }
});

document.addEventListener("change", async (e) => {
  const t = e.target;
  if (!DATA) return;
  if (t.id === "asAtInput") {
    if (!guardEdit()) { t.value = view.asAt || latestSnap().asAt; return; }
    const v = t.value;
    const latest = latestSnap();
    view.asAt = !v || v >= latest.asAt ? null : v;
    render();
  } else if (t.id === "compareSel") {
    view.compare = t.value; render();
  } else if (t.dataset.action === "trend-stream") {
    view.trendStream = t.value; render();
  } else if (t.dataset.action === "device-name") {
    try { localStorage.setItem("pub-device", t.value.trim() || "Browser"); toast("Device name saved."); } catch {}
  } else if (t.dataset.edit && view.editing) {
    // Refresh totals and warnings once a field is committed, keeping keyboard focus.
    rerenderKeepFocus();
  } else if (t.id === "restoreFile" && t.files[0]) {
    try {
      const obj = JSON.parse(await t.files[0].text());
      if (!Array.isArray(obj.snapshots) || !Array.isArray(obj.streams) || !obj.snapshots.length) throw new Error("That file is not a backup from this app.");
      if (!confirm(`Replace everything on the site with this backup (${obj.snapshots.length} snapshots)?`)) return;
      await commit((d) => { Object.keys(d).forEach((k) => delete d[k]); Object.assign(d, clone(obj)); d.reviewers = d.reviewers || []; }, `Restored from a backup with ${obj.snapshots.length} snapshots`);
      endEdit(); view.asAt = null; render(); toast("Backup restored.");
    } catch (err) { toast(err.message); }
    t.value = "";
  }
});

function rerenderKeepFocus() {
  setTimeout(() => {
    const a = document.activeElement;
    let sel = null;
    if (a && a.dataset && a.dataset.edit) {
      sel = `[data-edit="${a.dataset.edit}"][data-stream="${CSS.escape(a.dataset.stream)}"]`
        + (a.dataset.stage ? `[data-stage="${a.dataset.stage}"]` : "")
        + (a.dataset.rev ? `[data-rev="${CSS.escape(a.dataset.rev)}"]` : "");
    }
    render();
    if (sel) {
      const n = document.querySelector(sel);
      if (n) { n.focus(); try { n.select(); } catch {} }
    }
  }, 0);
}

window.addEventListener("beforeunload", (e) => {
  if (view.editing && draftChanges().length) { e.preventDefault(); e.returnValue = ""; }
});

/* ---------- dialogs ---------- */
function snapMetaDialog(id) {
  const s = DATA.snapshots.find((x) => x.id === id);
  openModal("Date and note", `
    <div class="field"><label for="smDate">As at</label><input id="smDate" type="date" value="${esc(s.asAt)}"></div>
    <div class="field"><label for="smNote">Note</label><input id="smNote" type="text" maxlength="200" value="${esc(s.note || "")}"></div>
    <div class="modal-actions"><button class="btn ghost" data-action="close-modal">Cancel</button><button class="btn primary" id="smGo">Save</button></div>`);
  $("#smGo").addEventListener("click", async () => {
    const d = $("#smDate").value;
    const note = $("#smNote").value.trim();
    if (!d) { toast("Choose a date."); return; }
    if (DATA.snapshots.some((x) => x.asAt === d && x.id !== id)) { toast("Another snapshot already has that date. Delete one first."); return; }
    try {
      await commit((data) => { const x = data.snapshots.find((y) => y.id === id); x.asAt = d; x.note = note; },
        d !== s.asAt ? `Moved the snapshot for ${fmtDate(s.asAt)} to ${fmtDate(d)}` : `Edited the note on the snapshot for ${fmtDate(d)}`);
      closeModal(); render();
    } catch (err) { toast(err.message); }
  });
}

function changePassDialog() {
  openModal("Change passcode", `
    <div class="field"><label for="cpA">New passcode</label><input id="cpA" type="password" autocomplete="new-password"></div>
    <div class="field"><label for="cpB">Confirm new passcode</label><input id="cpB" type="password" autocomplete="new-password"></div>
    <p class="small muted">Everything is re-encrypted with the new passcode, and the site token changes. If PUBLICATION_TOKEN is set in Netlify, update it to the new token straight afterwards and redeploy, otherwise the site will reject the new passcode.</p>
    <div class="modal-actions"><button class="btn ghost" data-action="close-modal">Cancel</button><button class="btn primary" id="cpGo">Change passcode</button></div>`);
  $("#cpGo").addEventListener("click", async () => {
    const a = $("#cpA").value, b = $("#cpB").value;
    if (a.length < 8) { toast("Use at least 8 characters."); return; }
    if (a !== b) { toast("The passcodes do not match."); return; }
    $("#cpGo").disabled = true;
    try {
      const newSalt = crypto.getRandomValues(new Uint8Array(16));
      const newKey = await deriveKey(a, newSalt);
      const newToken = await siteToken(a);
      const next = clone(DATA);
      next.changeLog = next.changeLog || [];
      next.changeLog.unshift({ at: new Date().toISOString(), device: deviceName(), text: "Changed the passcode" });
      const payload = await encryptData(next, newKey, newSalt);
      const res = await apiPut(payload, VERSION);   // authorised with the old token
      DATA = next; VERSION = res.version; KEY = newKey; SALT = newSalt; TOKEN = newToken;
      closeModal(); render();
      toast("Passcode changed. Update PUBLICATION_TOKEN in Netlify to the new token.", 7000);
    } catch (err) { $("#cpGo").disabled = false; toast(err.message); }
  });
}

/* ---------- start ---------- */
if (!window.crypto?.subtle) {
  $("#gateMsg").textContent = "This page needs a secure (https) connection to work.";
} else {
  initGate();
}
