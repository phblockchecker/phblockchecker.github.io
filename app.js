// Where the probe publishes (the repo's `data` branch); local preview reads pi/out/
const DATA_URL = location.hostname === "localhost"
  ? "pi/out/"
  : "https://raw.githubusercontent.com/phblockchecker/phblockchecker.github.io/data/";
const STALE_HOURS = 3;

const LEVELS = {
  open: ["Open", (net) => `Works normally on ${net}.`],
  dns: ["Blocked by DNS", (net) => `${net}'s DNS blocks it. Switching to encrypted DNS fixes it.`],
  hard: ["Blocked", () => "Blocked past DNS, so changing DNS won't help. You'll need a VPN."],
  unknown: ["Unknown", () => "The test couldn't finish this run."],
};
const TLS_LABELS = { sni: "filtered by name", ip: "IP blocked", tampered: "tampered", unknown: "untested" };

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  node.append(...children);
  return node;
}

function ago(iso) {
  const mins = Math.round((Date.now() - new Date(iso)) / 60000);
  if (mins < 60) return `${mins} min ago`;
  const hrs = Math.round(mins / 60);
  return hrs < 48 ? `${hrs} hr ago` : `${Math.round(hrs / 24)} days ago`;
}

async function load(file) {
  const res = await fetch(`${DATA_URL}${file}?t=${Date.now()}`, { cache: "no-store" });
  if (!res.ok) throw new Error(`${file}: ${res.status}`);
  return res.json();
}

function check(label, ok) {
  return el("li", { class: ok ? "yes" : "no", "data-mark": ok ? "✓" : "✗" }, label);
}

function renderSite(site, s, net, history) {
  const [label, explain] = LEVELS[s.level];
  const tlsBad = Object.values(s.tls).filter((t) => t !== "ok");
  const connLabel = tlsBad.length ? `Connection (${TLS_LABELS[tlsBad[0]]})` : "Connection";

  const strip = el("div", { class: "history", role: "img", "aria-label": `${site.name} history` });
  for (const h of history) {
    const lvl = h.levels[site.name] || "unknown";
    strip.append(el("span", { class: lvl, title: `${new Date(h.t).toLocaleString()} · ${LEVELS[lvl][0]}` }));
  }

  return el("article", { class: "card" },
    el("div", { class: "card-head" }, el("h3", {}, site.name), el("span", { class: `pill ${s.level}` }, label)),
    el("p", { class: "explain" }, explain(net)),
    el("ul", { class: "checks" },
      check(`${net} DNS`, s.isp_dns),
      check("Other DNS", s.alt_dns),
      check("Encrypted DNS", s.encrypted_dns),
      check(connLabel, !tlsBad.length)),
    strip,
    el("div", { class: "history-legend" }, el("span", {}, history.length ? ago(history[0].t) : ""), el("span", {}, "now")));
}

function resolverCell(res) {
  if (!res) return el("td", {}, el("span", { class: "pill na" }, "—"));
  if (res.status === "down") return el("td", {}, el("span", { class: "pill na", title: res.detail }, "No reply"));
  const all = Object.entries(res.domains);
  const blocked = all.filter(([, d]) => d.status !== "ok");
  const pill = blocked.length
    ? el("span", { class: "pill hard", title: blocked.map(([n, d]) => `${n}: ${d.detail}`).join("\n") }, `Blocked ${blocked.length}/${all.length}`)
    : el("span", { class: "pill open" }, "OK");
  return el("td", {}, pill);
}

function render(data, history) {
  const net = data.network;
  document.querySelectorAll("[data-network]").forEach((n) => (n.textContent = net));
  document.getElementById("meta").textContent = `Measured from a home ${net} connection · updated ${ago(data.updated)}`;
  document.getElementById("stale").hidden = Date.now() - new Date(data.updated) < STALE_HOURS * 3600e3;

  const levels = Object.values(data.summary).map((s) => s.level);
  document.getElementById("sites").replaceChildren(
    ...data.sites.map((site) => renderSite(site, data.summary[site.name], net, history)));

  document.getElementById("fix-intro").textContent = [
    levels.every((l) => l === "open") ? "Nothing is blocked right now. If that changes, these steps help." : "Switch to encrypted DNS. It's free and takes a minute.",
    data.dns_intercepted ? `Heads up: ${net} is hijacking plain DNS, so just typing in 1.1.1.1 won't work. Use the encrypted options below.` : "",
  ].join(" ");
  document.getElementById("vpn-note").hidden = !levels.includes("hard");

  document.getElementById("resolvers").replaceChildren(...data.resolvers.map((r) =>
    el("tr", {},
      el("td", {}, r.name, el("span", { class: "ip" }, r.ip || "encrypted only")),
      ...["udp", "dot", "doh"].map((t) => resolverCell(r.results[t])))));
}

Promise.all([load("latest.json"), load("history.json").catch(() => [])])
  .then(([data, history]) => render(data, history))
  .catch((err) => {
    document.getElementById("meta").textContent = "Couldn't load results. Try again later.";
    console.error(err);
  });
