// Where the probe publishes (the repo's `data` branch); local preview reads pi/out/
const DATA_URL = location.hostname === "localhost"
  ? "pi/out/"
  : "https://raw.githubusercontent.com/phblockchecker/phblockchecker.github.io/data/";
const STALE_HOURS = 1;

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

function check(label, ok, ...extra) {
  const [cls, mark] = ok == null ? ["unk", "?"] : ok ? ["yes", "✓"] : ["no", "✗"];
  return el("li", { class: cls, "data-mark": mark }, label, ...extra);
}

function renderSite(site, s, net, history) {
  const [label, explain] = LEVELS[s.level];
  const tlsBad = Object.values(s.tls).filter((t) => t !== "ok");
  const connLabel = tlsBad.length ? `Connection (${TLS_LABELS[tlsBad[0]]})` : "Connection";

  const strip = el("div", { class: "history", role: "img", "aria-label": `${site.name} history` });
  for (const h of history) {
    const lvl = h.levels[site.name] || "unknown";
    strip.append(withTip(el("span", { class: lvl }), () => [`${new Date(h.t).toLocaleString()} · ${LEVELS[lvl][0]}`]));
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
    el("div", { class: "history-legend" }, el("span", {}, history.length ? ago(history[0].t) : ""), el("span", {}, history.length ? ago(history.at(-1).t) : "")));
}

const clean = (res) => res?.status === "up" && Object.values(res.domains).every((d) => d.status === "ok");
const provider = (name) => name.replace(/ \(.*\)$/, "");

function chip(value, label) {
  const node = el("button", { class: "chip", type: "button", title: "Copy" }, el("code", {}, value), el("span", {}, label));
  node.addEventListener("click", () => navigator.clipboard?.writeText(value).then(() => {
    node.classList.add("copied");
    setTimeout(() => node.classList.remove("copied"), 1200);
  }));
  return node;
}

function renderWorking(data) {
  const others = data.resolvers.filter((r) => !r.isp);
  const hosts = new Map(others.filter((r) => r.tls_host && clean(r.results.dot)).map((r) => [r.tls_host, provider(r.name)]));
  const none = () => el("span", { class: "muted" }, "None right now.");
  const plain = others.filter((r) => clean(r.results.udp)).map((r) => chip(r.ip, provider(r.name)));
  document.getElementById("plain-ok").replaceChildren(...(plain.length ? plain : [none()]));
  document.getElementById("dot-ok").replaceChildren(...(hosts.size ? [...hosts].map(([h, n]) => chip(h, n)) : [none()]));

  const hijacked = others.filter((r) => data.hijacked?.includes(r.name));
  const note = document.getElementById("hijacked-note");
  note.hidden = !hijacked.length;
  note.textContent = `Don't use: ${hijacked.map((r) => `${r.ip} (${provider(r.name)})`).join(", ")}. ${data.network} is hijacking plain DNS sent to these and returning its block page.`;
}

// One shared, fixed-position tooltip so the table's scroll box doesn't clip it
const tip = el("div", { class: "tip", role: "tooltip", hidden: "" });
document.body.append(tip);
const hideTip = () => (tip.hidden = true);
addEventListener("scroll", hideTip, { passive: true, capture: true });

// Second line under a domain: block page address, why, and its title
function domainDetail(d) {
  if (d.status === "ok") return [];
  const page = d.detail.match(/^(likely )?block page (\S+)(?: \((.+)\))?$/);
  if (!page) return [el("div", { class: "tip-detail" }, d.status === "error" ? `No response · ${d.detail}` : d.detail)];
  const [, likely, addr, why] = page;
  return [el("div", { class: "tip-detail" },
    el("span", { class: "tip-tag" }, likely ? "Likely block page" : "Block page"), el("code", {}, addr), why ? ` · ${why}` : ""),
    ...(d.title ? [el("div", { class: "tip-detail tip-title" }, `“${d.title}”`)] : [])];
}

// Show the shared tooltip on hover/tap; content() returns its children
function withTip(node, content) {
  const show = () => {
    tip.replaceChildren(...content());
    tip.hidden = false;
    const r = node.getBoundingClientRect();
    const below = r.bottom + 6 + tip.offsetHeight < innerHeight;
    tip.style.left = `${Math.max(16, Math.min(r.left, innerWidth - tip.offsetWidth - 16))}px`;
    tip.style.top = `${below ? r.bottom + 6 : r.top - tip.offsetHeight - 6}px`;
  };
  node.tabIndex = 0;
  for (const e of ["mouseenter", "focus"]) node.addEventListener(e, show);
  for (const e of ["mouseleave", "blur"]) node.addEventListener(e, hideTip);
  return node;
}

// Hover/tap a pill to see ✓/✗/? per domain, grouped by site
const withDomains = (pill, res, sites) => withTip(pill, () => sites.map((s) => el("section", {},
  el("div", { class: "tip-site" }, s.name),
  el("ul", { class: "checks" }, ...s.domains.filter((n) => res.domains[n]).map((n) =>
    check(el("span", {}, n), { ok: true, blocked: false }[res.domains[n].status], ...domainDetail(res.domains[n])))))));

function resolverCell(res, sites) {
  if (!res) return el("td", {}, el("span", { class: "pill na" }, "—"));
  if (res.status === "down") return el("td", {}, el("span", { class: "pill na", title: res.detail }, "No reply"));
  if (clean(res)) return el("td", {}, el("span", { class: "pill open" }, "OK"));
  const names = sites.filter((s) => s.domains.some((d) => res.domains[d]?.status === "blocked")).map((s) => s.name);
  return el("td", {}, withDomains(names.length
    ? el("span", { class: "pill hard" }, `${names.join(", ")} blocked`)
    : el("span", { class: "pill na" }, "—"), res, sites));
}

function render(data, history) {
  const net = data.network;
  document.querySelectorAll("[data-network]").forEach((n) => (n.textContent = net));
  document.getElementById("meta").textContent = `Measured from a home ${net} 5G connection · updated ${ago(data.updated)}`;
  document.getElementById("stale").hidden = Date.now() - new Date(data.updated) < STALE_HOURS * 3600e3;

  const levels = Object.values(data.summary).map((s) => s.level);
  document.getElementById("sites").replaceChildren(
    ...data.sites.map((site) => renderSite(site, data.summary[site.name], net, history)));

  const hijackedNames = [...new Set((data.hijacked || []).map(provider))].join(", ");
  document.getElementById("fix-intro").textContent = [
    levels.every((l) => l === "open") ? "Nothing is blocked right now. If that changes, these steps help." : "Switch to encrypted DNS. It's free and takes a minute.",
    data.dns_intercepted ? `Heads up: ${net} is hijacking plain DNS${hijackedNames ? ` to ${hijackedNames}` : ""}, so just typing in 1.1.1.1 won't work. The regular DNS servers listed as working above will do for now, but encrypted DNS is the long-term fix.` : "",
  ].join(" ");
  renderWorking(data);
  document.getElementById("vpn-note").hidden = !levels.includes("hard");

  document.getElementById("resolvers").replaceChildren(...data.resolvers.map((r) =>
    el("tr", {},
      el("td", {}, r.name, el("span", { class: "ip" }, r.ip || (r.isp ? "via your home router" : "encrypted only"))),
      ...["udp", "dot", "doh"].map((t) => resolverCell(r.results[t], data.sites)))));
}

// Pulsing placeholders shaped like the real content, shown until the data loads
const bone = (cls, width) => el("span", { class: `skel ${cls}`, ...(width && { style: `width: ${width}px` }) });

function renderSkeletons() {
  document.getElementById("sites").replaceChildren(...[0, 1].map(() => el("article", { class: "card", "aria-hidden": "true" },
    el("div", { class: "card-head" }, bone("skel-title"), bone("skel-pill")),
    bone("skel-line"),
    el("div", { class: "skel-checks" }, ...[90, 100, 120, 100].map((w) => bone("skel-text", w))),
    bone("skel-history"))));
  for (const id of ["plain-ok", "dot-ok"])
    document.getElementById(id).replaceChildren(...[150, 120, 160, 130].map((w) => bone("skel-chip", w)));
  document.getElementById("resolvers").replaceChildren(...[140, 110, 170, 90, 130, 150, 100, 120].map((w) =>
    el("tr", { "aria-hidden": "true" }, el("td", {}, bone("skel-text", w), bone("skel-ip")), ...[0, 1, 2].map(() => el("td", {}, bone("skel-cell"))))));
}

renderSkeletons();
Promise.all([load("latest.json"), load("history.json").catch(() => [])])
  .then(([data, history]) => render(data, history))
  .catch((err) => {
    document.getElementById("meta").textContent = "Couldn't load results. Try again later.";
    for (const id of ["sites", "resolvers", "plain-ok", "dot-ok"]) document.getElementById(id).replaceChildren();
    console.error(err);
  });
