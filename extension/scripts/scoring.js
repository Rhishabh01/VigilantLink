// Local Scoring Engine for VigilantLink
// Implements the Bayesian local scoring system, risk levels, and explanations

var VERDICT_YELLOW_THRESHOLD = 35;
var VERDICT_RED_THRESHOLD = 65;

var GSB_MIN_SCORES = {
  "MALWARE": 95,
  "SOCIAL_ENGINEERING": 90,
  "POTENTIALLY_HARMFUL_APPLICATION": 80,
  "UNWANTED_SOFTWARE": 75
};

var TRUSTED_DOMAINS = [
  "google.com", "youtube.com", "github.com", "microsoft.com",
  "cloudflare.com", "discord.com", "linkedin.com", "apple.com"
];

function calculateLocalScore(heuristics, feedMatch, gsbMatch = null, impersonation = null, brandDistance = null, pathQuery = null) {
  const explanations = [];
  
  // ── Prior Probability of Phishing/Malicious URL ─────────────────────────
  // We assume a baseline prior probability of 2% for analyzed links.
  const priorProbability = 0.02;
  let odds = priorProbability / (1 - priorProbability); // prior odds ≈ 0.0204

  // ── 1. Typosquatting & Homoglyphs (Bayes Factor) ─────────────────────────
  if (heuristics.typosquatting) {
    const isHomoglyph = heuristics.typosquattingReason && heuristics.typosquattingReason.includes("Homoglyph");
    const factor = isHomoglyph ? 60.0 : 15.0;
    odds *= factor;
    explanations.push(heuristics.typosquattingReason || "Domain resembles brand domain (possible typosquatting)");
  }
  
  // ── 2. Punycode / Homoglyph ──────────────────────────────────────────────
  if (heuristics.punycode) {
    odds *= 6.0;
    explanations.push("Contains deceptive Unicode characters (Punycode)");
  }
  
  // ── 3. Suspicious keywords density ───────────────────────────────────────
  if (heuristics.keywordsCount && heuristics.keywordsCount > 0) {
    let factor = 1.0;
    if (heuristics.keywordsCount >= 3) {
      factor = 15.0;
      explanations.push("High density of suspicious security keywords");
    } else if (heuristics.keywordsCount === 2) {
      factor = 5.0;
      explanations.push(`Contains multiple suspicious keywords (${heuristics.keywordsCount} matches)`);
    } else {
      factor = 2.2;
      explanations.push("URL contains suspicious security keyword");
    }
    odds *= factor;
  }
  
  // ── 4. Excessive subdomains ──────────────────────────────────────────────
  if (heuristics.excessiveSubdomains) {
    odds *= 2.5;
    explanations.push("Excessive subdomain depth detected");
  }
  
  // ── 5. IP Address ────────────────────────────────────────────────────────
  if (heuristics.isIP) {
    odds *= 12.0;
    explanations.push("Uses a raw IP address instead of a domain name");
  }
  
  // ── 6. Entropy ───────────────────────────────────────────────────────────
  if (heuristics.highEntropy) {
    odds *= 2.0;
    explanations.push("High URL name entropy (randomized characters)");
  }
  
  // ── 7. Credentials in URL ────────────────────────────────────────────────
  if (heuristics.hasCredentials) {
    odds *= 8.0;
    explanations.push("Deceptive credentials embedded in URL");
  }
  
  // ── 8. Redirect Chain ────────────────────────────────────────────────────
  if (heuristics.redirectChainLength > 3) {
    odds *= 4.0;
    explanations.push("Suspiciously long redirect chain (> 3 hops)");
  }
  
  // ── 9. Suspicious TLD ────────────────────────────────────────────────────
  if (heuristics.suspiciousTLD) {
    const penalty = heuristics.tldWeight || 20;
    const factor = 1.0 + (penalty / 10.0); // e.g. penalty 35 -> factor 4.5
    odds *= factor;
    explanations.push(`Uses a high-risk suspicious TLD (${heuristics.tld}, +${penalty} points)`);
  }
  
  // ── Heuristic Correlation Synergies & Density Bonuses ────────────────────
  // TLD + Keyword Synergy
  if (heuristics.suspiciousTLD && heuristics.keywordsCount && heuristics.keywordsCount > 0) {
    odds *= 3.0;
    explanations.push("Suspicious TLD paired with security keywords");
  }
  
  // TLD + Excessive Subdomains
  if (heuristics.suspiciousTLD && heuristics.excessiveSubdomains) {
    odds *= 2.5;
    explanations.push("Suspicious TLD combined with excessive subdomains");
  }
  
  // Typosquatting + Keywords Synergy
  if (heuristics.typosquatting && heuristics.keywordsCount && heuristics.keywordsCount > 0) {
    odds *= 2.0;
  }
  
  // Raw IP + Keywords Synergy
  if (heuristics.isIP && heuristics.keywordsCount && heuristics.keywordsCount > 0) {
    odds *= 3.0;
  }
  
  // ── 10. Local feed match ─────────────────────────────────────────────────
  if (feedMatch) {
    odds *= 100.0;
    if (feedMatch.source === 'URLHaus') {
      explanations.push("Known phishing URL from URLHaus");
    } else {
      explanations.push("Matched local PhishTank database");
    }
  }
  
  // ── 11. Brand impersonation ──────────────────────────────────────────────
  if (impersonation) {
    odds *= 25.0;
    explanations.push(impersonation.reason);
  }
  
  // ── 12. Brand distance scoring ───────────────────────────────────────────
  if (brandDistance) {
    const alreadyFlagged = heuristics.typosquatting || impersonation;
    if (!alreadyFlagged) {
      let factor = 1.0;
      if (brandDistance.compositeScore >= 85) {
        factor = 30.0;
      } else if (brandDistance.compositeScore >= 70) {
        factor = 10.0;
      } else {
        factor = 3.0;
      }
      odds *= factor;
      explanations.push(brandDistance.reason);
    } else {
      odds *= 2.0; // Corroboration boost
    }
  }
  
  // Brand distance + Suspicious TLD synergy
  if (brandDistance && heuristics.suspiciousTLD) {
    odds *= 3.0;
    explanations.push("Brand-mimicking domain on suspicious TLD");
  }
  
  // Brand distance + Keywords synergy
  if (brandDistance && heuristics.keywordsCount && heuristics.keywordsCount > 0) {
    odds *= 2.0;
  }
  
  // ── 13. Path & query parameter analysis ──────────────────────────────────
  if (pathQuery && pathQuery.score > 0) {
    const factor = 1.0 + (pathQuery.score / 5.0); // e.g. score 40 -> factor 9.0
    odds *= factor;
    for (const exp of pathQuery.explanations) {
      explanations.push(exp);
    }
  }
  
  // ── 14. Disposable Domain Check ──────────────────────────────────────────
  if (heuristics.isDisposable) {
    odds *= 15.0;
    explanations.push("Uses a disposable/temporary domain name");
  }
  
  // ── 15. Keyword Bigrams ──────────────────────────────────────────────────
  if (heuristics.keywordBigramsCount && heuristics.keywordBigramsCount > 0) {
    const factor = 1.0 + (heuristics.keywordBigramsCount * 2.0);
    odds *= factor;
    explanations.push("URL matches suspicious keyword combinations");
  }
  
  // ── 16. Context Modifier (Trusted Domain Abuse Mitigation) ────────────────
  let contextModifier = 1.0;
  const isTrusted = TRUSTED_DOMAINS.some(d => heuristics.domain === d || heuristics.domain.endsWith('.' + d));
  if (isTrusted) {
    const hasStrongIndicator = feedMatch || gsbMatch || impersonation || heuristics.typosquatting;
    if (!hasStrongIndicator) {
      contextModifier = 0.05; // 20x decrease in odds for trusted hosts
    }
  }
  odds *= contextModifier;

  // ── Posterior Probability & Risk Score calculation ────────────────────────
  const posteriorProbability = odds / (1.0 + odds);
  let riskScore = Math.round(posteriorProbability * 100);
  
  // Clamping
  riskScore = Math.max(0, Math.min(100, riskScore));
  
  // ── 17. GSB Authoritative Override ───────────────────────────────────────
  if (gsbMatch) {
    const minScore = GSB_MIN_SCORES[gsbMatch] || 90;
    riskScore = Math.max(riskScore, minScore);
    explanations.push(`Deceptive site flagged by Google Safe Browsing (${gsbMatch})`);
  }
  
  // Determine verdict and safe properties
  let verdictClass = 'green';
  let safe = true;
  let riskLevel = 'Safe';
  
  if (riskScore >= VERDICT_RED_THRESHOLD) {
    verdictClass = 'red';
    safe = false;
    riskLevel = 'Dangerous';
  } else if (riskScore >= VERDICT_YELLOW_THRESHOLD) {
    verdictClass = 'yellow';
    safe = false;
    riskLevel = 'Suspicious';
  } else if (riskScore > 25) {
    riskLevel = 'Low Risk';
  }
  
  // Confidence determination
  let confidenceLevel = 'Medium';
  const indicatorsCount = (heuristics.typosquatting ? 1 : 0) + 
                          (heuristics.punycode ? 1 : 0) + 
                          (heuristics.keywords ? 1 : 0) + 
                          (feedMatch ? 1 : 0) + 
                          (impersonation ? 1 : 0) + 
                          (gsbMatch ? 1 : 0) +
                          (brandDistance ? 1 : 0) +
                          (pathQuery && pathQuery.score > 0 ? 1 : 0);
  
  if (indicatorsCount >= 2 || feedMatch || gsbMatch) {
    confidenceLevel = 'High';
  } else if (indicatorsCount === 0 || (indicatorsCount === 1 && riskScore < VERDICT_YELLOW_THRESHOLD)) {
    confidenceLevel = 'Low';
  }
  
  // Determine warning threat type
  let threatType = null;
  if (verdictClass === 'red' || verdictClass === 'yellow') {
    if (gsbMatch) {
      threatType = `Deceptive Site (${gsbMatch})`;
    } else if (feedMatch) {
      threatType = `Malicious Link (${feedMatch.source})`;
    } else if (impersonation || heuristics.typosquatting || (brandDistance && brandDistance.compositeScore >= 70)) {
      threatType = "Social Engineering / Impersonation";
    } else if (brandDistance) {
      threatType = "Suspected Brand Spoofing";
    } else if (pathQuery && pathQuery.flags && (pathQuery.flags.indexOf('OPEN_REDIRECT') !== -1 || pathQuery.flags.indexOf('CREDENTIAL_PARAMS') !== -1)) {
      threatType = "Suspicious URL Structure";
    } else if (heuristics.punycode) {
      threatType = "Deceptive Domain Name";
    } else {
      threatType = "Suspicious Link Activity";
    }
  }
  
  return {
    v: verdictClass,
    safe: safe,
    rs: riskScore,
    r: explanations,
    tt: threatType,
    confidence: confidenceLevel,
    level: riskLevel
  };
}
