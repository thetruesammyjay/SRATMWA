/* ── Shared JS helpers ── */
const API = {
  get: (url) => fetch(url).then(r => r.json()),
  post: (url, body) => fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }).then(r => r.json()),
  put: (url, body) => fetch(url, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }).then(r => r.json()),
  delete: (url) => fetch(url, { method: "DELETE" }).then(r => r.json()),
};

function badge(text, cls) {
  return `<span class="badge badge-${cls}">${text}</span>`;
}

function riskBadge(level) {
  const map = { Critical: "critical", High: "high", Medium: "medium", Low: "low" };
  return badge(level, map[level] || "info");
}

function statusBadge(status) {
  const map = { Open: "open", Mitigated: "mitigated", Accepted: "accepted", Closed: "mitigated",
                "In Progress": "info", Transferred: "info", "Not Implemented": "open",
                Implemented: "mitigated", "Partially Implemented": "high",
                Pass: "pass", Fail: "fail", "N/A": "na", "Not Checked": "na" };
  return badge(status, map[status] || "info");
}

function severityBadge(s) {
  const map = { Critical: "critical", High: "high", Medium: "medium", Low: "low", Informational: "na" };
  return badge(s, map[s] || "info");
}

function openModal(id) { document.getElementById(id).classList.add("open"); }
function closeModal(id) { document.getElementById(id).classList.remove("open"); }

function showAlert(msg, type = "success", containerId = "alert-container") {
  const el = document.getElementById(containerId);
  if (!el) return;
  el.innerHTML = `<div class="alert alert-${type}">${msg}</div>`;
  setTimeout(() => { el.innerHTML = ""; }, 3500);
}

function setActive(path) {
  document.querySelectorAll(".nav-link").forEach(a => {
    a.classList.toggle("active", a.getAttribute("href") === path);
  });
}

document.addEventListener("DOMContentLoaded", () => {
  setActive(window.location.pathname);
});
