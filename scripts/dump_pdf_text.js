"use strict";
const fs = require("fs");
const path = require("path");
const pdfParse = require("pdf-parse");

(async () => {
  const pdfPath = process.argv[2];
  if (!pdfPath) {
    console.error("Usage: node scripts/dump_pdf_text.js /path/to.pdf");
    process.exit(2);
  }
  const full = path.resolve(pdfPath);
  const buf = fs.readFileSync(full);
  const parsed = await pdfParse(buf);
  const text = String(parsed.text || "").replace(/\r/g, "");
  const lines = text.split("\n").map(l => l.replace(/\s+$/,""));
  for (let i = 0; i < Math.min(lines.length, 220); i++) {
    console.log(String(i+1).padStart(4," ") + " | " + lines[i]);
  }
})().catch(e => {
  console.error(e && e.stack ? e.stack : e);
  process.exit(1);
});
