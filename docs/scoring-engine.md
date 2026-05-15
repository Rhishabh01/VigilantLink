# Scoring Engine

Risk scores are integers from 0–100. Verdict thresholds and signal weights are defined in `app/core/constants.py`.

---

## Verdict Classification

| Score Range | Verdict | Label |
|---|---|---|
| 0 – `VERDICT_YELLOW_THRESHOLD - 1` | `green` | Safe |
| `VERDICT_YELLOW_THRESHOLD` – `VERDICT_RED_THRESHOLD - 1` | `yellow` | Suspicious |
| `VERDICT_RED_THRESHOLD` – 100 | `red` | Dangerous |

Scores are capped at 100.

---

## Two Scoring Passes

### Pass 1 — `compute_heuristic_score` (Phase 1)

Uses only local CPU analysis. No external API data. Must complete in <1ms.

**Inputs:** heuristics dict, redirect hops, final URL, DNS status, metadata availability, SSL error flag.

**Signals applied:**

| Signal | Condition | Penalty |
|---|---|---|
| DNS failure | Domain does not resolve | +40 |
| Missing metadata | No OG/meta tags, not a trusted platform | +10 |
| Suspicious TLD | Domain ends in a high-risk TLD | +15 |
| Plain HTTP | Scheme is `http://` | +20 |
| SSL error | TLS handshake failed during redirect trace | +30 |
| Phishing keywords | Keywords found in URL path, title, or description | +10 |
| Keyword + suspicious domain synergy | Phishing keyword on suspicious TLD or typosquatted domain | +15 |
| Brand impersonation | Levenshtein distance = 1 from a high-value target | `WEIGHT_HEURISTIC × BRAND_PENALTY_SCORE` |
| Punycode/homograph | `xn--` detected in any hop | Hard floor at `PUNYCODE_MIN_SCORE` |
| TLD + keyword synergy | Suspicious TLD + high-risk keyword | `WEIGHT_HEURISTIC × SYNERGY_PENALTY_SCORE` |
| Excessive redirect depth | Hops > `MAX_REDIRECT_HOPS_FREE` | Per-hop penalty (cross-domain > same-domain) |
| Typosquatting (no brand overlap) | Detected without brand penalty | `WEIGHT_HEURISTIC × TYPOSQUATTING_PENALTY` |

### Pass 2 — `compute_final_score` (Phase 2)

Starts from the heuristic base score produced by Pass 1, then applies external signals.

**Additional signals applied:**

| Signal | Condition | Effect |
|---|---|---|
| Trusted domain abuse | Hosting domain + phishing keyword | Score floored at `VERDICT_YELLOW_THRESHOLD + 1` |
| Hosted phishing escalation | Suspicious path/param on trusted hosting platform | Score floored at `VERDICT_YELLOW_THRESHOLD + 5` |
| SSL cert age | Certificate issued recently | `WEIGHT_SSL_AGE × penalty` (tiered) |
| Domain age (RDAP) | Domain registered recently | `WEIGHT_RDAP_AGE × penalty` (tiered) |
| Google Safe Browsing | Match found | Score overridden to `GSB_THREAT_MIN_SCORES[threat_type]` |
| Uncertainty penalty | Timed-out sources × conditions | +2 to +5 per source |
| Trusted platform cap | Strong signals absent | Score capped at `TRUSTED_PLATFORM_CAP`, weak reasons removed |

---

## SSL Certificate Age Penalties

| Age | Penalty Constant |
|---|---|
| < `SSL_CERT_VERY_NEW_DAYS` | `SSL_CERT_VERY_NEW_PENALTY` |
| < `SSL_CERT_NEW_DAYS` | `SSL_CERT_NEW_PENALTY` |
| < `SSL_CERT_RECENT_DAYS` | `SSL_CERT_RECENT_PENALTY` |
| < `SSL_CERT_YOUNG_DAYS` | `SSL_CERT_YOUNG_PENALTY` |

If the domain shows no other risk signals (`typosquatting`, `punycode`, `synergy`, GSB match), the penalty is capped at 5 regardless of age. This prevents young-but-legitimate sites from false-positiving.

---

## Domain Age Penalties (RDAP)

| Age | Penalty Constant |
|---|---|
| < `NEWLY_REGISTERED_DAYS` | `NEWLY_REGISTERED_PENALTY` |
| < `RECENTLY_REGISTERED_DAYS` | `RECENTLY_REGISTERED_PENALTY` |

---

## Signal Weights

Weights are applied as multipliers before adding to the base score:

| Weight | Used for |
|---|---|
| `WEIGHT_HEURISTIC` | Brand penalty, synergy, typosquatting |
| `WEIGHT_SSL_AGE` | SSL certificate age penalty |
| `WEIGHT_REDIRECT_DEPTH` | Per-hop redirect penalty |
| `WEIGHT_RDAP_AGE` | Domain age penalty |

---


## GSB Authoritative Override

When Google Safe Browsing returns a match, `compute_final_score` overrides the accumulated score:

```python
risk_score = max(risk_score, GSB_THREAT_MIN_SCORES[gsb_threat_type])
```

`GSB_THREAT_MIN_SCORES` maps each threat type to a minimum score:

| Threat Type | Minimum Score |
|---|---|
| `MALWARE` | 95 |
| `SOCIAL_ENGINEERING` (phishing) | 90 |
| `UNWANTED_SOFTWARE` | 80 |
| `POTENTIALLY_HARMFUL_APPLICATION` | 75 |

This ensures GSB matches always produce at least a `red` verdict regardless of heuristic score.

---

## Trusted Platform Dampening

Domains matching `TRUSTED_PLATFORMS` (e.g., `github.com`, `google.com`) have their score capped at `TRUSTED_PLATFORM_CAP` unless any of the following strong signals are present:

- GSB match
- Redirect chain depth > `MAX_REDIRECT_HOPS_FREE`
- Punycode detected
- Brand penalty applied
- Hosted phishing signals active

When capping applies, reasons matching `WEAK_SIGNAL_PATTERNS` are also removed from the output to reduce noise.

---

## Hosted Phishing Detection

`detect_hosted_phishing` fires specifically for URLs on `TRUSTED_HOSTING_DOMAINS` (e.g., `pages.github.io`, `web.app`). It checks for:

| Signal | Description |
|---|---|
| `suspicious_path` | URL path starts with a known phishing-associated path |
| `deceptive_param` | Query parameter redirects to an untrusted domain |
| `redirect_chain_suspicious` | Hop chain passes through an untrusted domain |

Corroboration count aggregates all signals + phishing keywords. `active=True` triggers a score floor at `VERDICT_YELLOW_THRESHOLD + 5`.

---

## Uncertainty Penalty

Applied when external sources time out. Penalties are conditional — they do not blindly penalize every timeout:

**SSL timeout:** +2, only if `base_score >= VERDICT_YELLOW_THRESHOLD` or heuristics are suspicious.

**GSB / RDAP timeout:** +5 per timed-out source, only if:
- Two or more of these sources timed out, **or**
- Heuristics are suspicious (`typosquatting`, `punycode`, `synergy`, `suspicious_keywords`), **or**
- `base_score >= VERDICT_YELLOW_THRESHOLD - 5`

The uncertainty reason is **not** appended to `reasons[]` for green verdicts.

---

## Punycode Hard Floor

If punycode is detected in the final URL or any redirect hop, the risk score is raised to at least `PUNYCODE_MIN_SCORE` regardless of other signals. This reflects the high confidence that punycode in URLs represents a homograph attack.
