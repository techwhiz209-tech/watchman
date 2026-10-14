const $ = (id) => document.getElementById(id);
chrome.storage.sync.get({ apiUrl: "http://127.0.0.1:8471", token: "" }, (s) => {
  $("apiUrl").value = s.apiUrl;
  $("token").value = s.token;
});
$("save").addEventListener("click", () => {
  chrome.storage.sync.set({ apiUrl: $("apiUrl").value.trim(), token: $("token").value.trim() }, () => {
    $("saved").textContent = "saved";
    setTimeout(() => ($("saved").textContent = ""), 2000);
  });
});
