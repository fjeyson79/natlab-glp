"use strict";

// Biomers PDF parser – pure extraction module.
// Returns { supplier, order_no, po_no, parse_version, items, warnings }
// where `warnings` is an array of completeness-check objects (cross-item).
// Item-level chemistry warnings remain in each item's own .warnings array.

const pdfParse = require("pdf-parse");

// ---------------------------------------------------------------------------
// Private helpers (copied exactly from server.js parsing block)
// ---------------------------------------------------------------------------

function normSpace(x) { return String(x || "").replace(/\s+/g, " ").trim(); }
function compactSeq(x) { return String(x || "").replace(/\s+/g, "").trim(); }

function parseIntModMap(block) {
    const map = {};
    const lines = block.split(/\n/).map(l => l.trim()).filter(Boolean);

    let start = -1;
    for (let i = 0; i < lines.length; i++) {
        if (/^Int\.?\s*Mod\.?/i.test(lines[i])) { start = i; break; }
    }
    if (start === -1) return map;

    const chunk = lines.slice(start, start + 6).join(" ");
    const re = /(\b[5-8])\s*:\s*([^:]+?)(?=(\b[5-8]\s*:)|$)/g;
    let m;
    while ((m = re.exec(chunk)) !== null) {
        const k = m[1];
        const v = normSpace(m[2]);
        map[k] = v;
    }
    return map;
}

function intModToPrefixBase(v) {
    const vv = String(v || "");
    if (/2'\s*[-]?\s*OMe/i.test(vv)) {
        const base = (vv.match(/2'\s*[-]?\s*OMe\s*[-]?\s*([ACGTU])/i) || [])[1] || null;
        return base ? { prefix: "m", base: base.toUpperCase() } : null;
    }
    if (/2'\s*[-]?\s*F/i.test(vv)) {
        const base = (vv.match(/2'\s*[-]?\s*F\s*[-]?\s*d?([ACGTU])/i) || [])[1] || null;
        return base ? { prefix: "f", base: base.toUpperCase() } : null;
    }
    if (/Locked\s+Nuc\s+Acid/i.test(vv) || /^\+\s*[ACGTU]/.test(vv)) {
        const base = (vv.match(/\+\s*([ACGTU])/i) || [])[1] || null;
        return base ? { prefix: "l", base: base.toUpperCase() } : null;
    }
    return null;
}

function applyCase(base, reportedType) {
    if (!base) return base;
    if (reportedType === "RNA") return base.toLowerCase();
    return base.toUpperCase();
}

function detectWarnings2(sequence_raw_compact, reportedType, intMap) {
    const warnings = [];
    const hasT = /T/.test(sequence_raw_compact);
    const hasU = /U/.test(sequence_raw_compact);

    if (reportedType === "RNA" && hasT) warnings.push("REPORTED_RNA_BUT_HAS_T");
    if (reportedType === "DNA" && hasU) warnings.push("REPORTED_DNA_BUT_HAS_U");
    if (hasT && hasU) warnings.push("MIXED_T_AND_U_IN_RAW");

    const hasDigits = /[5-8]/.test(sequence_raw_compact);
    if (hasDigits) {
        const needed = ["5","6","7","8"].filter(k => sequence_raw_compact.includes(k));
        const missing = needed.filter(k => !intMap[k]);
        if (missing.length > 0) warnings.push("DIGITS_PRESENT_BUT_INTMOD_INCOMPLETE");
    }

    const mapVals = Object.values(intMap || {}).join(" ");
    const mapHasU = /\bU\b/i.test(mapVals) || /dU\b/i.test(mapVals);
    const mapHasT = /\bT\b/i.test(mapVals) || /dT\b/i.test(mapVals);
    if (reportedType === "DNA" && mapHasU) warnings.push("INTMOD_SUGGESTS_U_WITH_REPORTED_DNA");
    if (reportedType === "RNA" && mapHasT) warnings.push("INTMOD_SUGGESTS_T_WITH_REPORTED_RNA");

    return warnings;
}

function suggestChemistryCode(reportedType, intMap, warnings) {
    if (warnings.includes("MIXED_T_AND_U_IN_RAW") ||
        warnings.includes("REPORTED_RNA_BUT_HAS_T") ||
        warnings.includes("REPORTED_DNA_BUT_HAS_U") ||
        warnings.includes("INTMOD_SUGGESTS_U_WITH_REPORTED_DNA") ||
        warnings.includes("INTMOD_SUGGESTS_T_WITH_REPORTED_RNA")) {
        return "MIXED";
    }
    const vals = Object.values(intMap || {}).join(" ");
    if (/2'\s*[-]?\s*OMe/i.test(vals)) return "RNA_2OMe";
    if (/2'\s*[-]?\s*F/i.test(vals)) return "DNA_2F";
    if (/Locked\s+Nuc\s+Acid/i.test(vals) || /\+\s*[ACGTU]/.test(vals)) return "DNA_LNA";
    return reportedType === "RNA" ? "RNA_STD" : "DNA_STD";
}

function decodeSequenceNorm(sequence_raw_compact, reportedType, intMap) {
    let out = "";
    const digits = new Set(["5","6","7","8"]);
    for (const ch of sequence_raw_compact) {
        if (digits.has(ch)) {
            const defn = intMap[ch];
            if (!defn) { out += ch; continue; }
            const pb = intModToPrefixBase(defn);
            if (!pb) { out += ch; continue; }
            const baseCased = applyCase(pb.base, reportedType);
            out += pb.prefix + baseCased;
        } else if (/[ACGTU]/.test(ch)) {
            out += applyCase(ch, reportedType);
        } else {
            out += ch;
        }
    }
    return out;
}

function extractField(block, re) {
    const m = block.match(re);
    return m ? normSpace(m[m.length - 1]) : null;
}

function parseMods(block) {
    const five  = extractField(block, /(^|\n)\s*5'\s*[-–]?\s*Mod\.?\s*[:]?\s*([^\n]+)/im);
    const three = extractField(block, /(^|\n)\s*3'\s*[-–]?\s*Mod\.?\s*[:]?\s*([^\n]+)/im);
    const fluorophore = five  ? five.replace(/\s*\(.*?\)\s*/g, "").trim() : null;
    const quencher    = three ? three.replace(/\s*\(.*?\)\s*/g, "").trim() : null;
    return { fluorophore, quencher, mod5: five, mod3: three };
}

function parseQC(block) {
    const lines = (block || "").split(/\r?\n/).map(l => (l || "").trim()).filter(l => l.length > 0);

    function nextValueAfter(labelRe, maxLook = 8) {
        for (let i = 0; i < lines.length; i++) {
            if (!labelRe.test(lines[i])) continue;
            for (let j = i + 1; j < Math.min(lines.length, i + 1 + maxLook); j++) {
                const v = lines[j];
                if (!v) continue;
                if (/^(Length|MW\s*Calc\.|MW\s*Found|Tm|GC\s*Content|Ext\.?Coeff\.?|Yield|Vol\.f\.100pmol|Conc\.|Dissolved|Product|Aliquots)\b/i.test(v)) return null;
                return v;
            }
            return null;
        }
        return null;
    }

    const length_nt  = nextValueAfter(/^Length\b/i);
    const mw_calc    = nextValueAfter(/^MW\s*Calc\./i);
    const mw_found   = nextValueAfter(/^MW\s*Found/i);
    const tm         = nextValueAfter(/^Tm\b/i);
    const gc_content = nextValueAfter(/^GC\s*Content\b/i);
    const ext_coeff  = nextValueAfter(/^Ext\.?Coeff\.?/i);

    let yield_od = null, amount_nmol = null, mass_ug = null;
    for (let i = 0; i < lines.length; i++) {
        if (!/^Yield\b/i.test(lines[i])) continue;
        const vals = [];
        for (let j = i + 1; j < Math.min(lines.length, i + 14); j++) {
            const v = lines[j];
            if (/^(Vol\.f\.100pmol|Conc\.|Dissolved|Product|Aliquots)\b/i.test(v)) break;
            if (!v) continue;
            vals.push(v);
        }
        yield_od     = (vals.find(v => /\bOD\b/i.test(v))   || null);
        amount_nmol  = (vals.find(v => /\bnmol\b/i.test(v)) || null);
        mass_ug      = (vals.find(v => /μg|\bug\b/i.test(v)) || null);
        break;
    }

    return { length_nt, mw_calc, mw_found, tm, gc_content, ext_coeff, yield_od, amount_nmol, mass_ug };
}

// ===== Biomers deterministic vertical parsers (template-first) =====

function parseVerticalSection(blockLines, startRegex, labelRegexToKeyList, stopRegex) {
    let start = -1;
    for (let i = 0; i < blockLines.length; i++) {
        if (startRegex.test(blockLines[i])) { start = i; break; }
    }
    if (start < 0) return { keys: [], values: [], map: {} };

    const keys = [];
    let i = start;
    for (; i < Math.min(blockLines.length, start + 60); i++) {
        const t = blockLines[i];
        let k = null;
        for (const pair of labelRegexToKeyList) {
            if (pair[0].test(t)) { k = pair[1]; break; }
        }
        if (!k) break;
        keys.push(k);
    }

    const values = [];
    for (let j = i; j < Math.min(blockLines.length, i + 120); j++) {
        const t = blockLines[j];
        if (!t) continue;
        if (/^[-–]+$/.test(t)) continue;
        if (stopRegex && stopRegex.test(t)) break;
        values.push(t);
    }

    const map = {};
    for (let k = 0; k < keys.length; k++) map[keys[k]] = values[k] || null;
    return { keys, values, map };
}

function parseSynthesisVertical(blockLines) {
    const sec = parseVerticalSection(
        blockLines,
        /^Scale\b/i,
        [
            [/^Scale\b/i,               "scale"],
            [/^Purific\.?\b/i,          "purification"],
            [/^5'-Mod\.?\s*:?$/i,       "mod5"],
            [/^3'-Mod\.?\s*:?$/i,       "mod3"],
            [/^Delivery\s*state\b/i,    "delivery_state"]
        ],
        /^(Int\.\s*Mod\.|Length\b|MW\s*Calc\.|MW\s*Found|Tm\b|GC\s*Content|Ext\.?Coeff\.?|Yield\b|Aliquots\b|Product\b)\b/i
    );
    return {
        scale:          sec.map.scale          || null,
        purification:   sec.map.purification   || null,
        mod5:           sec.map.mod5           || null,
        mod3:           sec.map.mod3           || null,
        delivery_state: sec.map.delivery_state || null
    };
}

function parseQCVertical(blockLines) {
    const sec = parseVerticalSection(
        blockLines,
        /^Length\b/i,
        [
            [/^Length\b/i,          "length"],
            [/^MW\s*Calc\.?/i,      "mw_calc"],
            [/^MW\s*Found\b/i,      "mw_found"],
            [/^Tm\b/i,              "tm"],
            [/^GC\s*Content\b/i,    "gc_content"],
            [/^Ext\.?\s*Coeff\.?/i, "ext_coeff"],
            [/^Yield\b/i,           "yield"]
        ],
        /^(Vol\.f\.100pmol|Conc\.|Dissolved|Product|Aliquots\b)\b/i
    );

    const firstNum = (x) => {
        if (!x) return null;
        const m = String(x).match(/[0-9]+(?:[.,][0-9]+)?/);
        return m ? m[0] : null;
    };
    const mwFmt = (x) => { const n = firstNum(x); return n ? `${n}_g/mol` : null; };
    const tmFmt = (x) => { const n = firstNum(x); return n ? `${n}_°C` : null; };
    const gcFmt = (x) => {
        if (!x) return null;
        const t = String(x).replace(/\s+/g, "");
        const n = firstNum(t);
        if (!n) return null;
        return t.endsWith("%") ? t : `${n}%`;
    };
    const extFmt = (x) => { const n = firstNum(x); return n ? n : null; };

    return {
        Length:         firstNum(sec.map.length),
        MW_Calc:        mwFmt(sec.map.mw_calc),
        MW_Found:       mwFmt(sec.map.mw_found),
        Tm:             tmFmt(sec.map.tm),
        GC_content:     gcFmt(sec.map.gc_content),
        Ext_Coeff:      extFmt(sec.map.ext_coeff),
        _yield_label_seen: sec.keys.indexOf("yield") >= 0
    };
}

function parseYield(blockLines) {
    const firstNum = (x) => {
        if (!x) return null;
        const m = String(x).match(/[0-9]+(?:[.,][0-9]+)?/);
        return m ? m[0] : null;
    };
    for (let i = 0; i < blockLines.length; i++) {
        if (!/^Yield\b/i.test(blockLines[i])) continue;
        const window = [];
        for (let j = i + 1; j < Math.min(blockLines.length, i + 30); j++) {
            const t = blockLines[j];
            if (/^(Vol\.f\.100pmol|Conc\.|Dissolved|Product|Aliquots\b)\b/i.test(t)) break;
            if (/^(Length|MW\s*Calc\.|MW\s*Found|Tm|GC\s*Content|Ext\.?Coeff\.?|Yield)\b/i.test(t)) continue;
            window.push(t);
        }
        const od   = window.find(v => /\bOD\b/i.test(v))   || null;
        const nmol = window.find(v => /\bnmol\b/i.test(v)) || null;
        const ug   = window.find(v => /μg|\bug\b/i.test(v)) || null;
        return { OD: firstNum(od), nmol: firstNum(nmol), "μg": firstNum(ug) };
    }
    return { OD: null, nmol: null, "μg": null };
}

function parseAliquots(blockLines) {
    const out = [];
    for (let i = 0; i < blockLines.length; i++) {
        if (!/^Aliquots\b/i.test(blockLines[i])) continue;
        for (let j = i + 1; j < Math.min(blockLines.length, i + 60); j++) {
            const t = blockLines[j];
            const mm = t.match(/^\s*(\d+)\s*\.\s*.*?OD\s*:\s*([0-9]+(?:[.,][0-9]+)?)\s*,?\s*nmol\s*:\s*([0-9]+(?:[.,][0-9]+)?)\s*,?\s*(?:μg|ug)\s*:\s*([0-9]+(?:[.,][0-9]+)?)\s*\.?\s*$/i);
            if (!mm) continue;
            out.push({ index: parseInt(mm[1], 10), OD: mm[2], nmol: mm[3], "μg": mm[4] });
        }
        break;
    }
    return out;
}

function deriveName(mod5, mod3, type) {
    if (!mod5 || !mod3 || !type) return null;
    const m5u = String(mod5).toUpperCase();
    const left = m5u.includes("FAM") ? "Fam" : String(mod5).replace(/_/g, "");
    return `${left}-${type}-${mod3}`;
}

function cleanIntMods(intMap) {
    const cleanOne = (x) => {
        const t = (x || "").trim();
        if (!t) return "None";
        if (/^none$/i.test(t)) return "None";
        if (/solvent/i.test(t)) return "None";
        return t;
    };
    return {
        "5": cleanOne(intMap && intMap["5"]),
        "6": cleanOne(intMap && intMap["6"]),
        "7": cleanOne(intMap && intMap["7"]),
        "8": cleanOne(intMap && intMap["8"])
    };
}

// ===== End Biomers deterministic vertical parsers =====

// ---------------------------------------------------------------------------
// Mandatory field completeness check (does NOT modify items)
// ---------------------------------------------------------------------------

function validateMandatoryFields(items) {
    const warnings = [];
    for (let idx = 0; idx < items.length; idx++) {
        const it      = items[idx] || {};
        const idInfo  = it.ID_INFO  || {};
        const seqInfo = it.SEQUENCE_INFO || {};
        const ends    = it.SYNTHESIS_MODIFICATIONS_ENDS || {};
        const ints    = it.SYNTHESIS_MODIFICATIONS_INTERNAL;

        const synOligoNo = idInfo["SynthesisOligo#"];
        const seq        = seqInfo.sequence_5to3;
        const mod5       = ends["5_mod"];
        const mod3       = ends["3_mod"];

        const ctx = {
            item_index:        idx,
            synthesis_oligo_no: synOligoNo != null ? String(synOligoNo) : null
        };

        if (!synOligoNo) {
            warnings.push({ code: "MISSING_SYNTHESIS_OLIGO_NO", severity: "error",
                message: "SynthesisOligo# not found in PDF block", ...ctx });
        }

        if (!seq) {
            warnings.push({ code: "MISSING_SEQUENCE", severity: "error",
                message: "sequence_5to3 not found in PDF block", ...ctx });
        }

        if (!mod5) {
            warnings.push({ code: "MISSING_5_MOD", severity: "warn",
                message: "5' modification not found in PDF block", ...ctx });
        }

        if (!mod3) {
            warnings.push({ code: "MISSING_3_MOD", severity: "warn",
                message: "3' modification not found in PDF block", ...ctx });
        }

        // Internal mods: flag if the structure is absent entirely.
        // Positions that are "None" after cleanIntMods are expected/normal.
        if (!ints) {
            warnings.push({ code: "MISSING_INTERNAL_MODS", severity: "warn",
                message: "SYNTHESIS_MODIFICATIONS_INTERNAL structure absent", ...ctx });
        }
    }
    return warnings;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Parse a Biomers delivery PDF.
 * @param {Buffer} pdfBuffer  Raw PDF bytes
 * @returns {Promise<{
 *   supplier: string,
 *   order_no: string|null,
 *   po_no: string|null,
 *   parse_version: string,
 *   items: Array,
 *   warnings: Array
 * }>}
 */
async function parseBiomersPdf(pdfBuffer) {
    const parsed = await pdfParse(pdfBuffer);
    const text   = String(parsed.text || "").replace(/\r/g, "");

    // Best-effort: order + PO
    let order_no = null;
    let po_no    = null;
    const mOrder = text.match(/\bOrder\s*No\.?\s*[:#]?\s*([0-9]{6,})\b/i);
    if (mOrder) order_no = mOrder[1];

    const mPO = text.match(/\bP\.?O\.?\s*No\.?\s*[:#]?\s*([A-Za-z0-9\-_\/]+)\b/i);
    if (mPO) po_no = mPO[1];

    // Locate block headers: 00304503_30 RNA or 00304503_30 DNA
    const reHeader = /(^|\n)\s*([0-9]{6,}_[0-9]{1,4})\s+(RNA|DNA)\b/g;
    const headers  = [];
    let mh;
    while ((mh = reHeader.exec(text)) !== null) {
        headers.push({ pos: mh.index, canonical_id: mh[2], reported_polymer_type: mh[3] });
    }

    if (headers.length === 0) {
        return {
            supplier:      "BIOMERS",
            order_no,
            po_no,
            parse_version: "biomers_v1_raw",
            items:         [],
            warnings:      [{ code: "NO_HEADERS_FOUND", severity: "error",
                               message: "No oligo block headers found in PDF" }]
        };
    }

    const items = [];
    for (let idx = 0; idx < headers.length; idx++) {
        const h     = headers[idx];
        const start = h.pos;
        const end   = (idx + 1 < headers.length) ? headers[idx + 1].pos : text.length;
        const block = text.slice(start, end);

        const canonical_id          = h.canonical_id;
        const reported_polymer_type = h.reported_polymer_type;

        const seqm           = block.match(/5'\s*[-–]?\s*([^\n]+?)\s*[-–]?\s*3'/i);
        const sequence_raw   = seqm ? normSpace(seqm[1]) : null;
        const sequence_compact = sequence_raw ? compactSeq(sequence_raw).toUpperCase() : "";
        const int_mod_map    = parseIntModMap(block);
        const warnings = sequence_raw
            ? detectWarnings2(sequence_compact, reported_polymer_type, int_mod_map)
            : ["NO_SEQUENCE_FOUND"];

        // PI guard: suspect internal mod text in position 8 (solvent or QC contamination)
        const rawInt8 = (int_mod_map && int_mod_map["8"]) ? String(int_mod_map["8"]) : "";
        if (rawInt8 && /(DMSO|ACN|MeOH|EtOH|ethanol|methanol|acetonitrile|isopropanol|IPA|H2O|water|buffer|PBS|TE|Tris|EDTA|NaCl|dissolv|volume|vol|conc|concentration|nmol|OD|MW|Tm|Yield|Aliquot|Length|GC|Coeff|Ext)/i.test(rawInt8)) {
            warnings.push("INTMOD_POS8_SUSPECT_TEXT");
        }

        const sequence_norm_suggested  = sequence_raw
            ? decodeSequenceNorm(sequence_compact, reported_polymer_type, int_mod_map)
            : null;
        const chemistry_code_suggested = suggestChemistryCode(reported_polymer_type, int_mod_map, warnings);

        const mods = parseMods(block);
        const qc   = parseQC(block);

        const requires_pi_confirmation = warnings.length > 0;

        const blockLines = (block || "").split(/\r?\n/).map(l => (l || "").trim()).filter(l => l.length > 0);

        const syn = parseSynthesisVertical(blockLines);
        const qcR = parseQCVertical(blockLines);
        const yld = parseYield(blockLines);
        const ali = parseAliquots(blockLines);

        const normMod = (x) => {
            if (!x) return null;
            return String(x).trim()
                .replace(/\s+/g, "_")
                .replace(/-/g, "_")
                .replace(/[()]/g, "")
                .replace(/_+/g, "_");
        };

        const mod5 = normMod(syn.mod5);
        const mod3 = normMod(syn.mod3);

        const synNoMatch  = block.match(/Synthesis\s*Oligo#\s*:?\s*([0-9]+)/i);
        const syn_oligo_no = synNoMatch ? synNoMatch[1] : null;

        const internal_mods = cleanIntMods(int_mod_map);

        const seq_lower     = sequence_raw ? compactSeq(sequence_raw).toLowerCase() : null;
        const sequence_5to3 = seq_lower ? `5'_${seq_lower}_3'` : null;

        items.push({
            ID_INFO: {
                Name:            deriveName(mod5, mod3, reported_polymer_type || null),
                "Order#":        canonical_id,
                Type:            reported_polymer_type || null,
                "SynthesisOligo#": syn_oligo_no
            },
            SEQUENCE_INFO: {
                sequence_5to3
            },
            SYNTHESIS_INFO: {
                Scale:          syn.scale,
                Purification:   syn.purification
            },
            SYNTHESIS_MODIFICATIONS_ENDS: {
                "5_mod": mod5,
                "3_mod": mod3
            },
            SYNTHESIS_MODIFICATIONS_INTERNAL: internal_mods,
            SYNTHESIS_REPORT: {
                Length:     qcR.Length,
                MW_Calc:    qcR.MW_Calc,
                MW_Found:   qcR.MW_Found,
                Tm:         qcR.Tm,
                GC_content: qcR.GC_content,
                Ext_Coeff:  qcR.Ext_Coeff
            },
            SYNTHESIS_YIELD: yld,
            ALIQUOTS:        ali,
            warnings,
            requires_pi_confirmation
        });
    }

    const completenessWarnings = validateMandatoryFields(items);

    return {
        supplier:      "BIOMERS",
        order_no,
        po_no,
        parse_version: "biomers_v1_raw",
        items,
        warnings:      completenessWarnings
    };
}

module.exports = { parseBiomersPdf };
