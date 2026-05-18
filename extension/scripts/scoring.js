// Local Scoring Engine for VigilantLink
// Implements the weighted local scoring system, risk levels, and explanations

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

function calculateLocalScore(heuristics, feedMatch, gsbMatch = null, impersonation = null) {
  let riskScore = 0;
  const explanations = [];
  
  // 1. Typosquatting & Homoglyphs
  if (heuristics.typosquatting) {
    const isHomoglyph = heuristics.typosquattingReason && heuristics.typosquattingReason.includes("Homoglyph");
    if (isHomoglyph) {
      riskScore += 65; // High risk for homoglyphs spoofing popular brands
    } else {
      riskScore += 45; // Substantial risk for standard brand typosquatting
    }
    explanations.push(heuristics.typosquattingReason || "Domain resembles brand domain (possible typosquatting)");
  }
  
  // 2. Punycode / Homoglyph
  if (heuristics.punycode) {
    riskScore += 20;
    explanations.push("Contains deceptive Unicode characters (Punycode)");
  }
  
  // 3. Suspicious keywords density
  if (heuristics.keywordsCount && heuristics.keywordsCount > 0) {
    const penalty = Math.min(30, heuristics.keywordsCount * 12);
    riskScore += penalty;
    if (heuristics.keywordsCount > 1) {
      explanations.push(`Contains multiple suspicious keywords (${heuristics.keywordsCount} matches)`);
    } else {
      explanations.push("URL contains suspicious security keyword");
    }
  }
  
  // 4. Excessive subdomains
  if (heuristics.excessiveSubdomains) {
    riskScore += 15;
    explanations.push("Excessive subdomain depth detected");
  }
  
  // 5. IP Address
  if (heuristics.isIP) {
    riskScore += 35;
    explanations.push("Uses a raw IP address instead of a domain name");
  }
  
  // 6. Entropy
  if (heuristics.highEntropy) {
    riskScore += 10;
    explanations.push("High URL name entropy (randomized characters)");
  }
  
  // 7. Credentials in URL
  if (heuristics.hasCredentials) {
    riskScore += 25;
    explanations.push("Deceptive credentials embedded in URL");
  }
  
  // 8. Redirect Chain
  if (heuristics.redirectChainLength > 3) {
    riskScore += 15;
    explanations.push("Suspiciously long redirect chain (> 3 hops)");
  }
  
  // 9. Suspicious TLD
  if (heuristics.suspiciousTLD) {
    riskScore += 20;
    explanations.push(`Uses a high-risk suspicious TLD (${heuristics.tld})`);
  }
  
  // --- Heuristic Correlation Synergies & Density Bonuses ---
  // A. High Keyword Density Bonus
  if (heuristics.keywordsCount && heuristics.keywordsCount >= 3) {
    riskScore += 15;
    explanations.push("High density of suspicious security keywords");
  }
  
  // B. Suspicious TLD + Keyword Synergy
  if (heuristics.suspiciousTLD && heuristics.keywordsCount && heuristics.keywordsCount > 0) {
    riskScore += 15;
    explanations.push("Suspicious TLD paired with security keywords");
  }
  
  // C. Suspicious TLD + Excessive Subdomains
  if (heuristics.suspiciousTLD && heuristics.excessiveSubdomains) {
    riskScore += 15;
    explanations.push("Suspicious TLD combined with excessive subdomains");
  }
  
  // D. Typosquatting + Keywords Synergy
  if (heuristics.typosquatting && heuristics.keywordsCount && heuristics.keywordsCount > 0) {
    riskScore += 10;
  }
  
  // E. Raw IP + Keywords Synergy
  if (heuristics.isIP && heuristics.keywordsCount && heuristics.keywordsCount > 0) {
    riskScore += 15;
  }
  
  // 10. Local feed match
  if (feedMatch) {
    riskScore += 50;
    if (feedMatch.source === 'URLHaus') {
      explanations.push("Known phishing URL from URLHaus");
    } else {
      explanations.push("Matched local PhishTank database");
    }
  }
  
  // 11. Brand impersonation
  if (impersonation) {
    riskScore += 45;
    explanations.push(impersonation.reason);
  }
  
  // 11. Trusted domain abuse mitigation
  const isTrusted = TRUSTED_DOMAINS.some(d => heuristics.domain === d || heuristics.domain.endsWith('.' + d));
  if (isTrusted) {
    const hasStrongIndicator = feedMatch || gsbMatch || impersonation || heuristics.typosquatting;
    if (!hasStrongIndicator) {
      riskScore -= 40;
    }
  }
  
  // Clamping
  riskScore = Math.max(0, Math.min(100, riskScore));
  
  // 12. GSB authoritative override (secondary verification)
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
                          (gsbMatch ? 1 : 0);
  
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
    } else if (impersonation || heuristics.typosquatting) {
      threatType = "Social Engineering / Impersonation";
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
