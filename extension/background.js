/* Watchman background — quarantine badge. v0.1: polls every 5 minutes. */
async function poll() {
  try {
    const { apiUrl = "http://127.0.0.1:8471", token = "" } = await chrome.storage.sync.get(["apiUrl", "token"]);
    if (!token) return;
    const r = await fetch(apiUrl + "/agents", { headers: { "X-Watchman-Token": token } });
    if (!r.ok) return;
    const { agents } = await r.json();
    const q = agents.filter((a) => a.tier === "quarantine").length;
    chrome.action.setBadgeText({ text: q ? String(q) : "" });
    chrome.action.setBadgeBackgroundColor({ color: "#ff5d5d" });
  } catch (_) { /* registry not running — stay quiet */ }
}
chrome.alarms.create("watchman-poll", { periodInMinutes: 5 });
chrome.alarms.onAlarm.addListener((a) => { if (a.name === "watchman-poll") poll(); });
poll();
