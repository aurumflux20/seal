// A third party's verifier: ~30 lines of Node, no seal, no Python, no DSN.
import { createHash, createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";

function jcs(o) {
  if (o === null || typeof o !== "object") return JSON.stringify(o);
  if (Array.isArray(o)) return "[" + o.map(jcs).join(",") + "]";
  const keys = Object.keys(o).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return "{" + keys.map(k => JSON.stringify(k) + ":" + jcs(o[k])).join(",") + "}";
}

const [file, pubHex] = process.argv.slice(2);
const bundle = JSON.parse(readFileSync(file, "utf8"));
const spki = Buffer.concat([
  Buffer.from("302a300506032b6570032100", "hex"),   // SPKI prefix for Ed25519
  Buffer.from(pubHex, "hex"),
]);
const key = createPublicKey({ key: spki, format: "der", type: "spki" });

let ok = true;
bundle.certs.forEach((cert, i) => {
  const body = Object.fromEntries(
    Object.entries(cert).filter(([k]) => k !== "hash" && k !== "sig"));
  const digest = createHash("sha256").update(jcs(body), "utf8").digest("hex");
  const hashOk = digest === cert.hash;
  const sigOk = cert.sig
    ? verify(null, Buffer.from(cert.hash, "hex"), key, Buffer.from(cert.sig, "hex"))
    : false;
  console.log(`cert ${i}: hash ${hashOk ? "OK" : "FAIL"}  signature ${sigOk ? "OK" : "FAIL"}  tier=${cert.tier}`);
  ok = ok && hashOk && sigOk;
});
console.log(ok ? "receipt VERIFIED (in JavaScript)" : "receipt FAILED");
process.exit(ok ? 0 : 1);
