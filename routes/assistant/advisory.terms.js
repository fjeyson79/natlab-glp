// routes/assistant/advisory.terms.js
//
// Hand-curated NAT-Lab domain dictionary used by buildTopicMap() to detect
// candidate topics in portal evidence (filenames + extracted text).
//
// Hard rule: a term can become a researcher topic ONLY if PORTAL evidence
// matches it. Anything not in this list is invisible to topic detection —
// which is intentional: we want missed topics, never invented ones.
//
// Adding a term: pick the canonical label, then a small set of aliases
// (lowercase, no regex metacharacters). Matching is whole-word, case-
// insensitive — see routes/assistant/advisory.js#detectTermHits.

'use strict';

const TERMS = [
    // ---- oligonucleotide classes ----
    { term: 'LNA modifications',          aliases: ['lna', 'locked nucleic acid'] },
    { term: 'antisense oligonucleotides', aliases: ['aso', 'antisense', 'antisense oligonucleotide'] },
    { term: 'siRNA',                      aliases: ['sirna', 'small interfering rna'] },
    { term: 'miRNA',                      aliases: ['mirna', 'microrna', 'micro-rna'] },
    { term: 'mRNA',                       aliases: ['mrna', 'messenger rna'] },
    { term: 'sgRNA / CRISPR',             aliases: ['sgrna', 'crispr', 'cas9'] },
    { term: 'aptamers',                   aliases: ['aptamer', 'aptamers'] },
    { term: 'PNA',                        aliases: ['pna', 'peptide nucleic acid'] },
    { term: 'GalNAc conjugates',          aliases: ['galnac', 'gal-nac', 'n-acetylgalactosamine'] },

    // ---- backbone / sugar / base modifications ----
    { term: 'phosphorothioate backbone',  aliases: ['phosphorothioate', 'ps backbone', 'ps-modified'] },
    { term: '2\'-O-methyl',               aliases: ['2omethyl', '2-o-methyl', "2'ome", '2ome'] },
    { term: '2\'-fluoro',                 aliases: ['2fluoro', '2-fluoro', "2'f"] },
    { term: '2\'-MOE',                    aliases: ['moe', '2moe', '2-moe', "2'moe"] },
    { term: 'morpholino',                 aliases: ['morpholino', 'pmo'] },
    { term: 'modified bases',             aliases: ['modified base', 'modified bases', 'base modification'] },

    // ---- synthesis & chemistry ----
    { term: 'solid-phase synthesis',      aliases: ['solid phase synthesis', 'solid-phase synthesis', 'sps'] },
    { term: 'phosphoramidite coupling',   aliases: ['phosphoramidite', 'coupling step', 'amidite'] },
    { term: 'deprotection',               aliases: ['deprotection'] },
    { term: 'cleavage from support',      aliases: ['cleavage', 'cleaved from support'] },
    { term: 'HPLC purification',          aliases: ['hplc', 'rp-hplc', 'reverse phase hplc'] },
    { term: 'desalting',                  aliases: ['desalting', 'desalt'] },
    { term: 'lyophilization',             aliases: ['lyophilization', 'lyophilisation', 'lyophilized'] },

    // ---- analytical methods ----
    { term: 'MALDI-TOF MS',               aliases: ['maldi', 'maldi-tof', 'maldi tof', 'maldi-ms'] },
    { term: 'ESI-MS',                     aliases: ['esi', 'esi-ms', 'electrospray'] },
    { term: 'LC-MS',                      aliases: ['lc-ms', 'lcms', 'lc/ms', 'liquid chromatography mass'] },
    { term: 'timsTOF MS',                 aliases: ['timstof', 'tims-tof', 'tims tof'] },
    { term: 'UV-Vis quantification',      aliases: ['uv-vis', 'uv vis', 'a260', 'nanodrop'] },
    { term: 'gel electrophoresis',        aliases: ['gel electrophoresis', 'page', 'denaturing page', 'agarose gel'] },
    { term: 'capillary electrophoresis',  aliases: ['capillary electrophoresis', 'ce'] },
    { term: 'NMR',                        aliases: ['nmr', '1h nmr', '31p nmr'] },
    { term: 'Tm / melting curve',         aliases: ['melting temperature', 'tm value', 'melting curve', 'duplex stability'] },
    { term: 'CD spectroscopy',            aliases: ['cd spectroscopy', 'circular dichroism'] },

    // ---- cell / molecular biology ----
    { term: 'cell culture',               aliases: ['cell culture', 'culture media', 'passaging'] },
    { term: 'transfection',               aliases: ['transfection', 'lipofection', 'lipofectamine'] },
    { term: 'knockdown',                  aliases: ['knockdown', 'gene knockdown', 'silencing'] },
    { term: 'cellular uptake',            aliases: ['uptake', 'cellular uptake', 'internalization'] },
    { term: 'delivery',                   aliases: ['delivery', 'oligonucleotide delivery', 'aso delivery'] },
    { term: 'serum stability',            aliases: ['serum stability', 'nuclease stability', 'biostability'] },
    { term: 'in vitro assay',             aliases: ['in vitro'] },
    { term: 'in vivo study',              aliases: ['in vivo'] },
    { term: 'mouse model',                aliases: ['mouse', 'murine', 'mice'] },
    { term: 'rat model',                  aliases: ['rat', 'rats'] },
    { term: 'qPCR',                       aliases: ['qpcr', 'rt-qpcr', 'quantitative pcr'] },
    { term: 'PCR / primers',              aliases: ['pcr', 'primer design', 'primers'] },
    { term: 'Sanger sequencing',          aliases: ['sanger sequencing', 'sanger'] },
    { term: 'NGS sequencing',             aliases: ['ngs', 'next generation sequencing', 'illumina'] },
    { term: 'western blot',               aliases: ['western blot', 'immunoblot'] },
    { term: 'ELISA',                      aliases: ['elisa'] },
    { term: 'flow cytometry',             aliases: ['flow cytometry', 'facs'] },
    { term: 'microscopy / imaging',       aliases: ['microscopy', 'confocal', 'fluorescence imaging'] },

    // ---- biophysical & binding ----
    { term: 'binding affinity',           aliases: ['binding affinity', 'kd value', 'dissociation constant'] },
    { term: 'IC50',                       aliases: ['ic50', 'ec50'] },
    { term: 'dose-response',              aliases: ['dose response', 'dose-response', 'titration'] },
    { term: 'kinetics',                   aliases: ['kinetics', 'reaction kinetics'] },
    { term: 'SPR',                        aliases: ['spr', 'surface plasmon resonance'] },
    { term: 'ITC',                        aliases: ['itc', 'isothermal titration calorimetry'] },

    // ---- disease / target areas relevant to NAT-Lab ----
    { term: 'oncology / cancer',          aliases: ['oncology', 'cancer', 'tumor', 'tumour'] },
    { term: 'neurodegeneration',          aliases: ['neurodegeneration', 'neurodegenerative', 'alzheimer', 'parkinson', 'huntington', 'sma', 'als'] },
    { term: 'cardiovascular',             aliases: ['cardiovascular', 'cardiac'] },
    { term: 'metabolic / liver',          aliases: ['hepatocyte', 'liver', 'fibrosis', 'nash', 'nafld'] },
    { term: 'rare disease',               aliases: ['rare disease', 'orphan disease'] },
    { term: 'viral infection',            aliases: ['antiviral', 'sars-cov-2', 'covid', 'influenza', 'hepatitis'] },

    // ---- methodology / quality ----
    { term: 'controls / replicates',      aliases: ['negative control', 'positive control', 'replicate', 'triplicate', 'biological replicate', 'technical replicate'] },
    { term: 'statistics',                 aliases: ['statistical analysis', 'p-value', 'p value', 'standard deviation', 'std dev'] },
    { term: 'GLP compliance',             aliases: ['glp', 'good laboratory practice'] },
    { term: 'SOP authoring',              aliases: ['sop', 'standard operating procedure'] },
    { term: 'calibration',                aliases: ['calibration', 'calibration curve'] },
    { term: 'validation',                 aliases: ['validation', 'method validation', 'assay validation'] },
];

module.exports = { TERMS };
