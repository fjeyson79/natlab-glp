"use strict";

const fs = require("fs");
const path = require("path");

const { parseBiomersPdf } = require("../server/oligo/biomers_parser");

function usage() {
  console.error("Usage: node scripts/test_biomers_parser.js /absolute/or/relative/path/to.pdf");
  process.exit(2);
}

(async () => {
  const pdfPath = process.argv[2];
  if (!pdfPath) usage();

  const full = path.resolve(pdfPath);
  if (!fs.existsSync(full)) {
    console.error("File not found:", full);
    process.exit(2);
  }

  const buf = fs.readFileSync(full);
  const out = await parseBiomersPdf(buf);

  const items = Array.isArray(out.items) ? out.items : [];
  const packWarnings = Array.isArray(out.warnings) ? out.warnings : [];

  const needsPI = items.filter(it => it && it.requires_pi_confirmation).length;
  const missingSynNo = packWarnings.filter(w => w && w.code === "MISSING_SYNTHESIS_OLIGO_NO").length;
  const missingSeq   = packWarnings.filter(w => w && w.code === "MISSING_SEQUENCE").length;

  console.log("supplier:", out.supplier);
  console.log("order_no:", out.order_no);
  console.log("po_no:", out.po_no);
  console.log("parse_version:", out.parse_version);
  console.log("items:", items.length);
  console.log("items_requires_pi_confirmation:", needsPI);
  console.log("pack_warnings:", packWarnings.length, "(missing syn no:", missingSynNo, ", missing seq:", missingSeq, ")");

  if (items[0]) {
    console.log("\nfirst_item_ID_INFO:");
    console.log(JSON.stringify(items[0].ID_INFO, null, 2));

    console.log("\nfirst_item_template_sample:");
    const sample = {
      ID_INFO: items[0].ID_INFO,
      SEQUENCE_INFO: items[0].SEQUENCE_INFO,
      SYNTHESIS_INFO: items[0].SYNTHESIS_INFO,
      SYNTHESIS_MODIFICATIONS_ENDS: items[0].SYNTHESIS_MODIFICATIONS_ENDS,
      SYNTHESIS_MODIFICATIONS_INTERNAL: items[0].SYNTHESIS_MODIFICATIONS_INTERNAL,
      SYNTHESIS_REPORT: items[0].SYNTHESIS_REPORT,
      SYNTHESIS_YIELD: items[0].SYNTHESIS_YIELD,
      ALIQUOTS: items[0].ALIQUOTS,
      warnings: items[0].warnings,
      requires_pi_confirmation: items[0].requires_pi_confirmation
    };
    console.log(JSON.stringify(sample, null, 2));
  }
})().catch(err => {
  console.error("ERROR:", err && err.stack ? err.stack : err);
  process.exit(1);
});
