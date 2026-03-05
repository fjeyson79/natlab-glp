"use strict";
const fs = require("fs");
const path = require("path");
const pdfParse = require("pdf-parse");

function normText(s) {
  return String(s || "").replace(/\r/g, "");
}

(async () => {
  const pdfPath = process.argv[2];
  const canonical = process.argv[3] || "00304503_1";
  if (!pdfPath) {
    console.error("Usage: node scripts/debug_aliquots.js /path/to.pdf 00304503_1");
    process.exit(2);
  }

  const full = path.resolve(pdfPath);
  const buf = fs.readFileSync(full);
  const parsed = await pdfParse(buf);
  const text = normText(parsed.text);

  // Find the canonical header start and next header end
  const reHeader = /(^|\n)\s*([0-9]{6,}_[0-9]{1,4})\s+(RNA|DNA)\b/g;
  const headers = [];
  let m;
  while ((m = reHeader.exec(text)) !== null) {
    headers.push({ pos: m.index, id: m[2], type: m[3] });
  }
  const idx = headers.findIndex(h => h.id === canonical);
  if (idx < 0) {
    console.error("Header not found for", canonical);
    console.error("First headers:", headers.slice(0, 5).map(h => h.id));
    process.exit(1);
  }

  const start = headers[idx].pos;
  const end = (idx + 1 < headers.length) ? headers[idx + 1].pos : text.length;
  const block = text.slice(start, end);

  const blockLines = block
    .split(/\r?\n/)
    .map(l => (l || "").replace(/\u00B5/g, "u").trim())
    .filter(l => l.length > 0);

  const joinedAll = blockLines.join(" ");
  const lower = joinedAll.toLowerCase();

  const posH = lower.indexOf(canonical.toLowerCase());
  const posA = lower.indexOf("aliquots", posH >= 0 ? posH : 0);

  let joined = posA >= 0 ? joinedAll.slice(posA) : joinedAll;
  if (posA >= 0) {
    const posP = lower.indexOf("product for research use only", posA);
    if (posP > posA) joined = joinedAll.slice(posA, posP);
  }

  console.log("=== canonical ===", canonical);
  console.log("=== block first 30 lines ===");
  console.log(blockLines.slice(0, 30).map((l,i)=>String(i+1).padStart(2," ")+" | "+l).join("\n"));

  console.log("\n=== joined slice (first 500 chars) ===");
  console.log(joined.slice(0, 500));

  console.log("\n=== regex matches ===");
  const re = /(\d+)\s*:\s*[\s\S]*?\(\s*([0-9]+(?:[\.,][0-9]+)?)\s*nmol\b/gi;
  let mm;
  while ((mm = re.exec(joined)) !== null) {
    console.log("match:", { index: mm[1], nmol: mm[2], at: mm.index });
  }
})();
