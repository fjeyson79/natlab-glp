// Institutional email domain rules per affiliation.
// Domains are matched exactly (case-insensitive) against the part after '@'.
// Affiliations not listed here (e.g. EXTERNAL) have no domain restriction.

const AFFILIATION_EMAIL_DOMAINS = {
    LiU: ['liu.se', 'student.liu.se'],
    UNAV: ['unav.es', 'alumni.unav.es'],
};

function normalizeEmail(email) {
    return String(email || '').trim().toLowerCase();
}

function getEmailDomain(email) {
    const normalized = normalizeEmail(email);
    const parts = normalized.split('@');
    if (parts.length !== 2 || !parts[0] || !parts[1]) return null;
    return parts[1];
}

function isEmailAllowedForAffiliation(email, affiliation) {
    const allowed = AFFILIATION_EMAIL_DOMAINS[affiliation];
    if (!allowed) return true;
    const domain = getEmailDomain(email);
    return domain !== null && allowed.includes(domain);
}

function affiliationDomainError(affiliation) {
    const allowed = AFFILIATION_EMAIL_DOMAINS[affiliation] || [];
    return `${affiliation} affiliation requires ${allowed.map(d => '@' + d).join(' or ')} email`;
}

module.exports = {
    AFFILIATION_EMAIL_DOMAINS,
    normalizeEmail,
    getEmailDomain,
    isEmailAllowedForAffiliation,
    affiliationDomainError,
};
