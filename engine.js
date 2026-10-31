/**
 * PhishGuard Client-Side Fallback Engine
 * Identical 12 deterministic heuristic detectors as the Python backend.
 * Automatically activates when running in serverless static environments without backend compute.
 */

const KNOWN_SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "rb.gy", "is.gd", "goo.gl", "ow.ly",
  "buff.ly", "cutt.ly", "rebrand.ly", "bl.ink", "shorturl.at"
]);

const TOP_BRANDS = [
  "microsoft", "google", "paypal", "apple", "amazon", "netflix",
  "facebook", "instagram", "github", "linkedin", "dropbox", "chase",
  "bankofamerica", "wellsfargo"
];

const PHISH_KEYWORDS = [
  "login", "signin", "verify", "verification", "security", "secure",
  "account", "billing", "update", "support", "service", "portal",
  "authentication", "auth", "center", "review", "suspended"
];

function levenshteinDistance(s1, s2) {
  if (s1.length < s2.length) return levenshteinDistance(s2, s1);
  if (s2.length === 0) return s1.length;
  let prevRow = Array.from({ length: s2.length + 1 }, (_, i) => i);
  for (let i = 0; i < s1.length; i++) {
    const currRow = [i + 1];
    for (let j = 0; j < s2.length; j++) {
      const cost = s1[i] === s2[j] ? 0 : 1;
      currRow.push(Math.min(currRow[j] + 1, prevRow[j + 1] + 1, prevRow[j] + cost));
    }
    prevRow = currRow;
  }
  return prevRow[prevRow.length - 1];
}

function clientAnalyzeUrl(rawUrl) {
  const analysisId = Math.random().toString(36).substring(2, 10);
  const now = new Date().toUTCString().replace("GMT", "UTC");
  const raw = (rawUrl || "").trim();

  let parsed;
  try {
    parsed = new URL(raw.includes("://") ? raw : "http://" + raw);
  } catch (e) {
    return {
      analysis_id: analysisId,
      timestamp: now,
      url: raw,
      sanitized_url: "[INVALID]",
      indicator_count: 0,
      classification: "NO LISTED WARNING SIGNS",
      findings: [],
      safe_next_steps: ["Please provide a valid, well-formed URL string."],
      limitations: "URL parsing rejected: Invalid URL structure."
    };
  }

  const host = parsed.hostname.toLowerCase();
  const scheme = raw.includes("://") ? raw.split("://")[0].toLowerCase() : "";
  const findings = [];

  // Check 1: @ Symbol
  const hasAt = raw.includes("@");
  findings.push({
    check_id: "CHECK_1_AT_SYMBOL",
    name: "@ Symbol in URL",
    detected: hasAt,
    evidence: hasAt ? "@ symbol found in authority or URL body" : null,
    why_it_matters: "The '@' symbol separates user-information authentication syntax from the actual destination hostname in URI RFC 3986.",
    limitations: "Legitimate authentication endpoints may occasionally contain '@'.",
    agent_name: "Structure Analysis Agent"
  });

  // Check 2: Length > 100
  const isLong = raw.length > 100;
  findings.push({
    check_id: "CHECK_2_URL_LENGTH",
    name: "Unusually Long URL",
    detected: isLong,
    evidence: isLong ? `URL length is ${raw.length} characters (threshold: 100)` : null,
    why_it_matters: "Unusually long URLs (exceeding 100 characters) are frequently used in phishing to push the true destination out of view.",
    limitations: "Many legitimate web services legitimately exceed 100 characters.",
    agent_name: "Structure Analysis Agent"
  });

  // Check 3: Shorteners
  const isShortener = KNOWN_SHORTENERS.has(host);
  findings.push({
    check_id: "ADV_URL_SHORTENER",
    name: "URL Shortening Service",
    detected: isShortener,
    evidence: isShortener ? `Hostname '${host}' is a known public URL shortening service` : null,
    why_it_matters: "URL shortening services conceal the actual destination web address.",
    limitations: "Shorteners are widely used for legitimate convenience in social media.",
    agent_name: "Structure Analysis Agent"
  });

  // Check 4: Suspicious Query / Parameter Syntax
  let hasSuspiciousParams = false;
  let paramEvidence = null;
  const rawLower = raw.toLowerCase();
  if (parsed.search) {
    if (parsed.search.includes("http://") || parsed.search.includes("https://") || parsed.search.includes("%3a%2f%2f")) {
      hasSuspiciousParams = true;
      paramEvidence = "Potential open redirect: secondary external URL inside query parameters";
    } else if (["redirect", "next", "token", "session", "verify", "update", "password", "reset"].some(k => rawLower.includes(k))) {
      hasSuspiciousParams = true;
      paramEvidence = "Suspicious security/session/credential parameter triggers";
    }
  }
  findings.push({
    check_id: "ADV_SUSPICIOUS_PARAMS",
    name: "Suspicious Query / Parameter Syntax",
    detected: hasSuspiciousParams,
    evidence: paramEvidence,
    why_it_matters: "Parameters containing secondary external URLs or urgent session triggers are syntactic indicators frequently observed in deceptive links.",
    limitations: "Legitimate Single-Sign-On (SSO) workflows legitimately pass callback redirect URLs.",
    agent_name: "Structure Analysis Agent"
  });

  // Check 5: Obfuscated Encoding
  let hasObfuscation = false;
  let encEvidence = null;
  if (rawLower.includes("/../") || rawLower.includes("/%2e%2e/") || rawLower.includes("%252e%252e")) {
    hasObfuscation = true;
    encEvidence = "Directory traversal pattern ('../' or encoded dot-dot-slash) detected";
  } else if (rawLower.includes("<script") || rawLower.includes("%3cscript")) {
    hasObfuscation = true;
    encEvidence = "Embedded HTML/XSS tag ('<script>') detected in URL text";
  } else if ((parsed.pathname.match(/%[0-9a-fA-F]{2}/g) || []).length >= 3) {
    hasObfuscation = true;
    encEvidence = "Heavy percent-encoding obfuscating ASCII path";
  }
  findings.push({
    check_id: "ADV_SUSPICIOUS_ENCODING",
    name: "Obfuscated Encoding & Path Anomalies",
    detected: hasObfuscation,
    evidence: encEvidence,
    why_it_matters: "Attackers use double-encoding and directory traversal to bypass inspection filters. Note: PhishGuard inspects text statically and never executes code.",
    limitations: "Standard URL encoding is normal for non-ASCII characters.",
    agent_name: "Structure Analysis Agent"
  });

  // Check 6: IPv4 Hostname
  const isIpv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(host.replace(/[\[\]]/g, ""));
  findings.push({
    check_id: "CHECK_3_IPV4_HOST",
    name: "IP Address Hostname",
    detected: isIpv4,
    evidence: isIpv4 ? `Hostname '${host}' is a numeric IPv4 address` : null,
    why_it_matters: "Legitimate institutions use registered domain names. Phishing operators sometimes use bare IP addresses.",
    limitations: "Numeric IP addresses are standard in local networking.",
    agent_name: "Hostname Intelligence Agent"
  });

  // Check 7: Multiple Hostname Segments
  const segments = host.split(".").filter(Boolean);
  const manySegments = segments.length >= 5;
  findings.push({
    check_id: "CHECK_4_MANY_SEGMENTS",
    name: "Multiple Hostname Segments",
    detected: manySegments,
    evidence: manySegments ? `Hostname contains ${segments.length} dot-separated segments: [${segments.join(", ")}]` : null,
    why_it_matters: "Phishing links often chain excessive subdomains to deceive users.",
    limitations: "Complex CDNs and multi-tenant services legitimately possess 5+ segments.",
    agent_name: "Hostname Intelligence Agent"
  });

  // Check 8: Punycode
  const hasPunycode = segments.some(s => s.startsWith("xn--"));
  findings.push({
    check_id: "CHECK_5_PUNYCODE",
    name: "Punycode Encoded Hostname",
    detected: hasPunycode,
    evidence: hasPunycode ? "Punycode encoded label(s) found ('xn--')" : null,
    why_it_matters: "Punycode ('xn--') allows IDNs in ASCII. Attackers exploit homograph attacks with lookalike characters.",
    limitations: "Punycode is an open standard enabling non-Latin alphabets.",
    agent_name: "Hostname Intelligence Agent"
  });

  // Check 9: Typosquatting
  let isTyposquat = false;
  let typosquatEvidence = null;
  if (segments.length >= 2) {
    const sld = segments[segments.length - 2];
    const norm = sld.replace(/0/g, "o").replace(/1/g, "l").replace(/vv/g, "w");
    for (const brand of TOP_BRANDS) {
      if (norm === brand && sld !== brand) {
        isTyposquat = true;
        typosquatEvidence = `Character substitution / leetspeak spoof of '${brand}': '${sld}'`;
        break;
      }
      const cleaned = sld.replace(/[^a-z0-9]/g, "").replace(/0/g, "o").replace(/1/g, "l");
      if (cleaned.includes(brand) && !sld.includes(brand)) {
        isTyposquat = true;
        typosquatEvidence = `Lookalike variant of brand '${brand}' in label '${sld}'`;
        break;
      }
      if (sld.length >= 4 && Math.abs(sld.length - brand.length) <= 2) {
        const dist = levenshteinDistance(sld, brand);
        if (dist === 1 || (dist === 2 && brand.length >= 7 && [...sld].sort().join("") === [...brand].sort().join(""))) {
          isTyposquat = true;
          typosquatEvidence = `Typosquatting variant of '${brand}': '${sld}' (letter transposition / typo)`;
          break;
        }
      }
    }
  }
  findings.push({
    check_id: "ADV_TYPOSQUATTING",
    name: "Typosquatting & Lookalike Domain",
    detected: isTyposquat,
    evidence: typosquatEvidence,
    why_it_matters: "Typosquatting exploits typographical mistakes or character similarities to lure victims to counterfeit pages.",
    limitations: "Occasionally, distinct legitimate companies resemble established words.",
    agent_name: "Hostname Intelligence Agent"
  });

  // Check 10: Misleading Subdomain / Compound Brand
  let isMisleading = false;
  let misleadingEvidence = null;
  if (segments.length >= 2) {
    const registered = segments.slice(-2).join(".");
    const subdomains = segments.slice(0, -2);
    const sld = segments[segments.length - 2];
    for (const sub of subdomains) {
      for (const b of TOP_BRANDS) {
        if (sub === b || host.includes(`${b}.com`) || host.includes(`${b}.org`) || host.includes(`${b}.net`)) {
          if (!registered.startsWith(`${b}.`)) {
            isMisleading = true;
            misleadingEvidence = `Deceptive brand subdomain: '${b}' appears in subdomains, but actual controlling domain is '${registered}'`;
            break;
          }
        }
      }
      if (isMisleading) break;
    }
    if (!isMisleading && sld.includes("-")) {
      for (const b of TOP_BRANDS) {
        if (sld.includes(b)) {
          const matched = PHISH_KEYWORDS.filter(kw => sld.includes(kw));
          if (matched.length > 0) {
            isMisleading = true;
            misleadingEvidence = `Hyphenated brand spoof combining '${b}' with security keywords: [${matched.join(", ")}]`;
            break;
          }
        }
      }
    }
  }
  findings.push({
    check_id: "ADV_MISLEADING_DOMAIN_STRUCTURE",
    name: "Misleading Brand Subdomain / Compound Domain",
    detected: isMisleading,
    evidence: misleadingEvidence,
    why_it_matters: "Attackers place recognizable brand names in subdomains or create compound hyphenated domains.",
    limitations: "Authorized partners or campaign microsites occasionally use hyphenated domains.",
    agent_name: "Hostname Intelligence Agent"
  });

  // Check 11: HTTP Scheme
  const isHttp = scheme === "http";
  findings.push({
    check_id: "CHECK_6_HTTP_SCHEME",
    name: "Unencrypted HTTP Scheme",
    detected: isHttp,
    evidence: isHttp ? "Protocol scheme is 'http' (unencrypted plaintext)" : null,
    why_it_matters: "Standard HTTP transmits all data in unencrypted cleartext across the network.",
    limitations: "Modern phishing campaigns also acquire free SSL certificates. HTTPS does NOT prove safety.",
    agent_name: "Protocol Analysis Agent"
  });

  // Check 12: Port or Protocol Anomaly
  let hasPortAnomaly = false;
  let portEvidence = null;
  if (parsed.port && parsed.port !== "80" && parsed.port !== "443") {
    hasPortAnomaly = true;
    portEvidence = `Non-standard web port detected: ${parsed.port}`;
  } else if (scheme && scheme !== "http" && scheme !== "https") {
    hasPortAnomaly = true;
    portEvidence = `Unusual protocol scheme detected: '${scheme}://'`;
  }
  findings.push({
    check_id: "ADV_PROTOCOL_PORT_ANOMALY",
    name: "Non-Standard Port or Protocol Scheme",
    detected: hasPortAnomaly,
    evidence: portEvidence,
    why_it_matters: "Phishing servers often operate on non-standard ports or unusual protocols.",
    limitations: "Development and administration panels routinely use alternate ports.",
    agent_name: "Protocol Analysis Agent"
  });

  // Scoring
  const count = findings.filter(f => f.detected).length;
  let classification = "NO LISTED WARNING SIGNS";
  if (count >= 3) classification = "ELEVATED REVIEW";
  else if (count >= 1) classification = "REVIEW";

  const safeSteps = [
    "Never enter credentials or sensitive information on unverified sites.",
    "Inspect the true domain by searching for the official institution via a trusted search engine or bookmarks.",
    "If in doubt, contact the alleged sender through an independent, verified communication channel."
  ];
  if (count >= 3) {
    safeSteps.unshift("Avoid clicking or opening this link in a standard browser session.");
  }

  return {
    analysis_id: analysisId,
    timestamp: now,
    url: raw,
    sanitized_url: `${scheme ? scheme + "://" : ""}${host}${parsed.pathname || "/"}`,
    indicator_count: count,
    classification: classification,
    findings: findings,
    safe_next_steps: safeSteps,
    limitations: "Educational evaluation only. PhishGuard conducts local structural heuristic checks. It does not query live DNS, reputation databases, or inspect destination web content."
  };
}
