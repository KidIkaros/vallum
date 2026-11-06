// SPDX-License-Identifier: Apache-2.0

// The front-end renders; it does not decide. Every value arrives already
// allowlisted from the host, and every value is written with textContent —
// peer names and endpoints are attacker-influenced, so nothing here may build
// markup out of them.

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const $ = (id) => document.getElementById(id);

const COUNTERS = [
  ["datagrams_sent", "Datagrams out"],
  ["datagrams_failed", "Datagrams failed"],
  ["packets_delivered", "Packets in"],
  ["packets_failed", "Packets failed"],
  ["established", "Handshakes"],
  ["refusals", "Refused"],
  ["reassembled", "Reassembled"],
  ["fragments_dropped", "Fragments lost"],
];

/** A handshake older than this is almost certainly not carrying traffic. */
const STALE_AFTER_SECONDS = 180;

function formatAge(seconds) {
  if (!seconds) return "never";
  const delta = Math.max(0, Math.floor(Date.now() / 1000 - seconds));
  if (delta < 60) return delta + "s ago";
  if (delta < 3600) return Math.floor(delta / 60) + "m ago";
  if (delta < 86400) return Math.floor(delta / 3600) + "h ago";
  return Math.floor(delta / 86400) + "d ago";
}

function formatBytes(value) {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let scaled = Number(value) || 0;
  let unit = 0;
  while (scaled >= 1024 && unit < units.length - 1) {
    scaled /= 1024;
    unit += 1;
  }
  const digits = unit === 0 || scaled >= 100 ? 0 : 1;
  return scaled.toFixed(digits) + " " + units[unit];
}

function tag(text, tone) {
  const element = document.createElement("span");
  element.className = "tag";
  element.textContent = text;
  if (tone) element.dataset.tone = tone;
  return element;
}

function cell(text, className) {
  const element = document.createElement("td");
  element.textContent = text;
  if (className) element.className = className;
  return element;
}

function setState(text, health) {
  const state = $("state");
  state.textContent = text;
  if (health) state.dataset.health = health;
  else delete state.dataset.health;
}

function renderCounters(counters) {
  const host = $("counters");
  host.replaceChildren();
  for (const [key, label] of COUNTERS) {
    const box = document.createElement("div");
    box.className = "counter";
    const name = document.createElement("div");
    name.className = "label";
    name.textContent = label;
    const value = document.createElement("div");
    value.className = "value";
    value.textContent = String(counters[key] ?? 0);
    box.append(name, value);
    host.append(box);
  }
}

function renderPeers(peers) {
  const body = $("peers");
  body.replaceChildren();
  $("peer-count").textContent = String(peers.length);
  $("no-peers").hidden = peers.length > 0;

  for (const peer of peers) {
    const row = document.createElement("tr");

    const name = document.createElement("td");
    const nameText = document.createElement("span");
    nameText.className = "peer-name";
    nameText.textContent = peer.name || "unnamed";
    name.append(nameText);
    if (peer.rotating) name.append(tag("rotating", "warn"));
    if (peer.has_preshared_key) name.append(tag("psk", "accent"));
    row.append(name);

    row.append(cell(peer.endpoint || "—", "mono"));

    const allowed = document.createElement("td");
    if (peer.allowed_ips.length === 0) {
      allowed.textContent = "—";
    } else {
      for (const entry of peer.allowed_ips) {
        const line = document.createElement("span");
        line.className = "allowed";
        line.textContent = entry;
        allowed.append(line);
      }
    }
    row.append(allowed);

    const age = cell(formatAge(peer.last_handshake_sec), "num");
    if (
      peer.last_handshake_sec &&
      Date.now() / 1000 - peer.last_handshake_sec > STALE_AFTER_SECONDS
    ) {
      age.classList.add("stale");
    }
    row.append(age);
    row.append(cell(formatBytes(peer.tx_bytes), "num"));
    row.append(cell(formatBytes(peer.rx_bytes), "num"));
    body.append(row);
  }
}

function render(payload) {
  if (!payload) return;
  if (!payload.ok) {
    setState(payload.error || "control request failed", "bad");
    return;
  }
  const snapshot = payload.data;
  if (!snapshot) return;

  setState("live", "ok");
  $("empty").hidden = true;
  $("f-interface").textContent = snapshot.interface || "—";
  $("f-addresses").textContent = snapshot.addresses.length
    ? snapshot.addresses.join(", ")
    : "—";
  $("f-port").textContent = snapshot.listen_port ?? "—";
  $("f-suite").textContent = snapshot.suite || "—";
  $("f-fwmark").textContent = snapshot.fwmark ?? "none";
  $("f-fingerprint").textContent = snapshot.fingerprint || "—";

  renderCounters(snapshot.counters);
  renderPeers(snapshot.peers);
}

async function reportWindowState() {
  try {
    await invoke("window_state", {
      focused: document.hasFocus(),
      visible: document.visibilityState === "visible",
    });
  } catch (error) {
    console.error("window_state", error);
  }
}

async function boot() {
  await listen("snapshot", (event) => render(event.payload));

  const interfaces = await invoke("list_interfaces");
  const picker = $("interface");
  picker.replaceChildren();
  for (const entry of interfaces) {
    const option = document.createElement("option");
    option.value = entry.path;
    option.textContent = entry.name;
    picker.append(option);
  }

  if (interfaces.length === 0) {
    $("empty").hidden = false;
    setState("no daemon", "bad");
    return;
  }

  picker.addEventListener("change", () => invoke("select", { path: picker.value }));
  await invoke("select", { path: interfaces[0].path });
  await reportWindowState();
}

window.addEventListener("focus", reportWindowState);
window.addEventListener("blur", reportWindowState);
document.addEventListener("visibilitychange", reportWindowState);

boot().catch((error) => setState(String(error), "bad"));
