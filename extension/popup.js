/** Popup control surface: explicit start/stop and honest counters. */
function render(state) {
  const on = !!state.enabled;
  document.getElementById("status").textContent = on ? "COLLECTING" : "STOPPED";
  document.getElementById("status").style.color = on ? "#10b981" : "#94a3b8";
  document.getElementById("observed").textContent = state.stats.observed;
  document.getElementById("sent").textContent = state.stats.sent;
  document.getElementById("queued").textContent = state.queued;
  document.getElementById("failed").textContent = state.stats.failed;
  document.getElementById("endpoint").textContent = new URL(state.endpoint).host;

  const btn = document.getElementById("toggle");
  btn.textContent = on ? "Stop collection" : "Start collection";
  btn.className = on ? "off" : "on";
  btn.onclick = () =>
    chrome.runtime.sendMessage({ type: "setEnabled", enabled: !on }, refresh);

  document.getElementById("error").textContent = state.stats.lastError
    ? `Last error: ${state.stats.lastError}`
    : "";
}

function refresh() {
  chrome.runtime.sendMessage({ type: "getState" }, (s) => s && render(s));
}

document.getElementById("flush").onclick = () =>
  chrome.runtime.sendMessage({ type: "flushNow" }, refresh);

refresh();
setInterval(refresh, 2000);
