// ConWatch module SDK for Node.js (single file, no dependencies).
//
//   const { Module } = require("./conwatch-sdk");
//   const m = new Module();
//   m.on("connection_opened", ev => { if (ev.remote_port === 23) m.alert(`${ev.process} used telnet`, "critical"); });
//   m.run();
const readline = require("readline");

class Module {
  constructor() { this.handlers = {}; }
  on(type, fn) { (this.handlers[type] = this.handlers[type] || []).push(fn); }
  send(obj) { process.stdout.write(JSON.stringify(obj) + "\n"); }
  /** Needs the `alerts:emit` permission. level: info | warning | critical */
  alert(message, level = "info") { this.send({ action: "alert", level, message }); }
  log(message) { this.send({ action: "log", message }); }
  run() {
    readline.createInterface({ input: process.stdin }).on("line", line => {
      let ev;
      try { ev = JSON.parse(line); } catch { return; }
      for (const key of [ev.type, "*"]) (this.handlers[key] || []).forEach(fn => fn(ev));
    });
  }
}

module.exports = { Module };
