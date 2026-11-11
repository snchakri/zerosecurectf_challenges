// Node harness for the Latverian WASM gate validator.
// Usage:  node run.js '<candidate>'    (or pipe the candidate on stdin)
const fs = require('fs'), path = require('path');
const buf = fs.readFileSync(path.join(__dirname, 'validator.wasm'));
let cand;
if (process.argv[2] !== undefined) cand = Buffer.from(process.argv[2], 'latin1');
else cand = fs.readFileSync(0);
while (cand.length && (cand[cand.length - 1] === 10 || cand[cand.length - 1] === 13))
  cand = cand.slice(0, cand.length - 1);
WebAssembly.instantiate(buf).then(({ instance }) => {
  const mem = new Uint8Array(instance.exports.memory.buffer);
  mem.fill(0, 0, cand.length + 1);
  mem.set(cand, 0);
  const r = instance.exports.validate(cand.length);
  if (r === 1) { console.log('ACCEPTED: the citadel gate opens.'); process.exit(0); }
  console.log('REJECTED.'); process.exit(1);
}).catch(e => { console.error(e); process.exit(2); });
