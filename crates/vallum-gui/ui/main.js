// SPDX-License-Identifier: Apache-2.0

// The front-end renders; it does not decide. Every value arrives already
// allowlisted from the host, and every value is written with textContent —
// peer names and endpoints are attacker-influenced, so nothing here may build
// markup out of them.
//
// The same rule covers the forms. A write is a typed command with named
// arguments; there is no path from this file to the socket except through the
// commands the host registered, and no field the host did not ask for.

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

/** The last snapshot, so a form can start from what the daemon reported. */
let current = null;

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

function button(label, variant, onClick) {
  const element = document.createElement("button");
  element.type = "button";
  element.className = variant || "ghost";
  element.textContent = label;
  element.addEventListener("click", onClick);
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

/**
 * One peer's actions. Rotate and finalise change the stored identity, so they
 * need the config file; the host says so when it cannot read it.
 */
function peerActions(peer) {
  const group = document.createElement("div");
  group.className = "row-actions";
  group.append(
    button("Edit", "ghost", () => editPeer(peer)),
    button("Rotate", "ghost", () => rotatePeer(peer)),
  );
  if (peer.rotating) {
    group.append(button("Finalise", "ghost", () => finalizePeer(peer)));
  }
  group.append(button("Remove", "danger", () => removePeer(peer)));
  return group;
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

    const actions = document.createElement("td");
    actions.className = "num";
    actions.append(peerActions(peer));
    row.append(actions);

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

  current = snapshot;
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

// --------------------------------------------------------------------------
// Dialogs

function closeDialog() {
  $("dialog").close();
}

/**
 * A form dialog. `rows` are `[label, name, value, options]`, and `run` receives
 * the values by name and returns the host's answer. Errors are shown in place:
 * a refused write must not close the form the operator would have to retype.
 */
function openForm({ title, note, rows, submit, run }) {
  const dialog = $("dialog");
  $("dialog-title").textContent = title;
  const body = $("dialog-body");
  body.replaceChildren();

  const form = document.createElement("form");
  form.method = "dialog";

  const describe = document.createElement("p");
  describe.className = "note";
  describe.textContent = note;
  form.append(describe);

  const inputs = new Map();
  for (const [label, name, value, options] of rows) {
    const field = document.createElement("label");
    field.className = "field";
    const caption = document.createElement("span");
    caption.textContent = label;
    const input = document.createElement("input");
    input.name = name;
    input.value = value == null ? "" : String(value);
    input.type = options?.secret ? "password" : "text";
    input.autocomplete = "off";
    input.spellcheck = false;
    if (options?.mono) input.className = "mono";
    if (options?.placeholder) input.placeholder = options.placeholder;
    if (options?.readonly) input.readOnly = true;
    field.append(caption, input);
    form.append(field);
    inputs.set(name, input);
  }

  const problem = document.createElement("p");
  problem.className = "form-error";
  problem.hidden = true;
  form.append(problem);

  const footer = document.createElement("div");
  footer.className = "dialog-actions";
  const cancel = button("Cancel", "ghost", () => {
    dialog.close();
  });
  const apply = button(submit, "primary", async () => {
    problem.hidden = true;
    const values = {};
    for (const [name, input] of inputs) values[name] = input.value;
    apply.disabled = true;
    try {
      const done = await run(values);
      dialog.close();
      setState(done.message, "ok");
      if (done.command) showCommand(done.message, done.command);
    } catch (error) {
      problem.textContent = String(error);
      problem.hidden = false;
    } finally {
      apply.disabled = false;
    }
  });
  footer.append(cancel, apply);
  form.append(footer);
  body.append(form);
  dialog.showModal();
  inputs.values().next().value?.focus();
}

/** A confirmation for the writes that cannot be undone by clicking again. */
function openConfirm({ title, note, submit, run }) {
  const dialog = $("dialog");
  $("dialog-title").textContent = title;
  const body = $("dialog-body");
  body.replaceChildren();

  const describe = document.createElement("p");
  describe.className = "note";
  describe.textContent = note;

  const problem = document.createElement("p");
  problem.className = "form-error";
  problem.hidden = true;

  const footer = document.createElement("div");
  footer.className = "dialog-actions";
  const cancel = button("Cancel", "ghost", () => dialog.close());
  const go = button(submit, "danger", async () => {
    problem.hidden = true;
    go.disabled = true;
    try {
      const done = await run();
      dialog.close();
      setState(done.message, "ok");
    } catch (error) {
      problem.textContent = String(error);
      problem.hidden = false;
    } finally {
      go.disabled = false;
    }
  });
  footer.append(cancel, go);
  body.append(describe, problem, footer);
  dialog.showModal();
}

/** The invite's join command, which is the one thing worth copying. */
function showCommand(message, command) {
  const dialog = $("dialog");
  $("dialog-title").textContent = "Join ticket";
  const body = $("dialog-body");
  body.replaceChildren();

  const note = document.createElement("p");
  note.className = "note";
  note.textContent = message;

  const line = document.createElement("code");
  line.className = "command";
  line.textContent = command;

  const footer = document.createElement("div");
  footer.className = "dialog-actions";
  const copy = button("Copy", "primary", async () => {
    try {
      await navigator.clipboard.writeText(command);
      copy.textContent = "Copied";
    } catch {
      copy.textContent = "Select and copy";
    }
  });
  footer.append(button("Close", "ghost", closeDialog), copy);
  body.append(note, line, footer);
  dialog.showModal();
}

// --------------------------------------------------------------------------
// Writes

const PEER_ROWS = (peer) => [
  [
    "Public line",
    "public_line",
    peer?.public_line || "",
    { mono: true, readonly: Boolean(peer), placeholder: "vallum1:…" },
  ],
  ["Name", "name", peer?.name || "", { placeholder: "laptop" }],
  ["Endpoint", "endpoint", peer?.endpoint || "", { mono: true, placeholder: "198.51.100.7:51820" }],
  ["Allowed IPs", "allowed_ips", (peer?.allowed_ips || []).join(", "), { mono: true }],
  ["Keepalive (s)", "keepalive", peer?.keepalive ?? ""],
  [
    "PSK (hex, blank keeps)",
    "preshared_key",
    "",
    { secret: true, mono: true, placeholder: peer?.has_preshared_key ? "set" : "none" },
  ],
];

function addPeer() {
  openForm({
    title: "Add peer",
    note: "The peer's public line, and the addresses routed to it.",
    rows: PEER_ROWS(null),
    submit: "Add",
    run: (fields) => invoke("add_peer", { fields }),
  });
}

function editPeer(peer) {
  openForm({
    title: "Edit peer",
    note: "The identity is fixed here; use Rotate to change it.",
    rows: PEER_ROWS(peer),
    submit: "Save",
    run: (fields) => invoke("edit_peer", { fields }),
  });
}

function rotatePeer(peer) {
  openForm({
    title: "Rotate peer",
    note: "The peer's new public line. Its old key stays accepted until you finalise, so in-flight sessions survive.",
    rows: [
      ["Peer", "name", peer.name || "unnamed", { readonly: true }],
      ["New public line", "new_line", "", { mono: true, placeholder: "vallum1:…" }],
    ],
    submit: "Rotate",
    run: (values) => invoke("rotate_peer", { name: peer.name, newLine: values.new_line }),
  });
}

function finalizePeer(peer) {
  openConfirm({
    title: "Finalise rotation",
    note: `Retire the previous key for ${peer.name || "this peer"}? A peer still using it will not reconnect.`,
    submit: "Finalise",
    run: () => invoke("finalize_peer", { name: peer.name }),
  });
}

function removePeer(peer) {
  openConfirm({
    title: "Remove peer",
    note: `Remove ${peer.name || "this peer"} from the running device? The config file is unchanged.`,
    submit: "Remove",
    run: () => invoke("remove_peer", { publicLine: peer.public_line }),
  });
}

function editDevice() {
  openForm({
    title: "Runtime device settings",
    note: "Applied to the running daemon and not written to the config file.",
    rows: [
      ["Listen port", "listen_port", current?.listen_port ?? "", { mono: true }],
      ["Firewall mark", "fwmark", current?.fwmark ?? ""],
    ],
    submit: "Apply",
    run: (values) =>
      invoke("apply_device", {
        listenPort: values.listen_port,
        fwmark: values.fwmark,
      }),
  });
}

function invitePeer() {
  openForm({
    title: "Invite a peer",
    note: "Mints a one-time token. Hand the join command to the new peer; it expires on its own.",
    rows: [
      ["Name", "name", "", { placeholder: "laptop" }],
      ["TTL (minutes)", "ttl_minutes", "60"],
      [
        "Pinned public line (optional)",
        "pinned",
        "",
        { mono: true, placeholder: "only accept this identity" },
      ],
    ],
    submit: "Mint",
    run: (fields) => invoke("invite_peer", { fields }),
  });
}

// --------------------------------------------------------------------------
// Boot

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

  $("add-peer").addEventListener("click", addPeer);
  $("invite-peer").addEventListener("click", invitePeer);
  $("edit-device").addEventListener("click", editDevice);

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
