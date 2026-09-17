# Threat Model & Hardening Plan — chicken-road2.app

**Deliverable for:** Threat Model and Secure Configuration (Beginner, 45–60 min)
**Target:** `https://www.chicken-road2.app/` — casino-affiliate presentation site for "Chicken Road 2" (InOut Games)
**Scope:** Passive analysis of publicly observable DNS, HTTP headers, and site content (authorized)
**Date:** 2026-09-17

---

## 1. Architecture / Data Flow Diagram

```
                 TRUST BOUNDARY A: Public Internet
   [Visitor/Player] ──HTTPS──> [Cloudflare Edge (AS13335, WAF/DNS)]
                                      │  Trust Boundary B: edge → origin
                                      ▼
                           [Vercel hosting — Next.js app]
                                      │  Trust Boundary C: app → affiliate
                                      ▼
                     [/go/play redirect → promotions.superslots.ag]
                                      │
                                      ▼
                        [External casino (out of our control)]

   External dependencies:
     - Cloudflare (DNS, edge, TLS cert via Google Trust Services)
     - Vercel (origin hosting, Next.js)
     - SuperSlots affiliate network (btag=..., affid=112859)
     - Google Search Console (site-verification TXT)

   Data assets (by value):
     1. Domain reputation / visitor trust ("official presentation" claim)
     2. Brand identity ("Chicken Road 2")
     3. Affiliate commission integrity (btag/affid)
     4. SEO ranking / sitemap

   Stored data: none server-side (no auth, no DB, no forms)
   → Primary risk surface is TRUST & INTEGRITY, not confidentiality.
```

### Trust boundaries
| ID | Boundary | Notes |
|----|----------|-------|
| A | Visitor → Cloudflare edge | Public HTTPS, HSTS max-age=63072000 (no includeSubDomains/preload) |
| B | Cloudflare → Vercel origin | Origin hidden behind anycast; `x-vercel-id dub1::iad1`, `x-powered-by: Next.js` disclosed |
| C | Site → affiliate redirect | `/go/play` → `promotions.superslots.ag` with fixed btag/affid |
| D | Site ↔ impersonation cluster | chicken-road.net, .app, chickenroad2.casino, fake Play Store / App Store apps |

---

## 2. Threat List (STRIDE)

| # | STRIDE | Threat | Evidence |
|---|--------|--------|----------|
| S1 | Spoofing | Email spoofing / phishing "from" the domain | No SPF, no DMARC (`_dmarc` NXDOMAIN), no MX |
| S2 | Spoofing | Brand impersonation (APKs, look-alike domains) | Impersonation cluster + Play Store/App Store impostors |
| T1 | Tampering | Open redirect on `/go/play` if target ever becomes parameterized | btag/affid in redirect URL |
| T2 | Tampering | Malicious third-party script injection (if ads/affiliate JS added later) | No CSP to constrain script sources |
| R1 | Repudiation | No external audit trail of content changes | Vercel deploys untracked externally |
| I1 | Info disclosure | Stack fingerprinting | `x-powered-by: Next.js`, `x-vercel-id` headers |
| I2 | Info disclosure | Clickjacking / framing abuse | No CSP `frame-ancestors`, no `X-Frame-Options` |
| D1 | Denial of Service | Origin exhaustion | Mitigated: Cloudflare anycast hides origin; residual risk on redirect endpoint rate limits |
| E1 | Elevation of Privilege | Cloudflare/Vercel account takeover = full site + DNS control | Single choke point; MFA status unverified |
| E2 | Elevation of Privilege | Unrestricted cert issuance for the domain | No CAA record |

---

## 3. Risk Register (Likelihood × Impact)

| Risk | ID | Likelihood | Impact | Score | Priority |
|------|----|-----------|--------|-------|----------|
| Email spoofing / phishing from domain | S1 | High | High | **Critical** | **P1** |
| Clickjacking / framing abuse | I2 | Medium | Medium | High | P2 |
| Affiliate redirect tampering / open redirect | T1 | Medium | High | High | P2 |
| Cloudflare/Vercel account takeover | E1 | Low–Med | Critical | High | P2 |
| Brand / app-store impersonation cluster | S2 | High | Medium | Medium | P3 |
| HSTS gaps (no includeSubDomains/preload) | — | Low | Medium | Medium | P3 |
| Missing XCTO / Referrer-Policy / Permissions-Policy | — | High | Low | Medium | P3 |
| RTP misinformation (site: 98% vs official: 96%) — trust/regulatory | — | Medium | Medium | Medium | P3 |
| Stack disclosure, no CAA, stale robots.txt, malformed contact email | I1/E2 | High | Low | Low | P4 |

**Positives already in place:** Cloudflare origin hiding, partial HSTS, NEL/report-to, `cache-control: private/no-store`, minimal subdomain surface (only apex + www), HTTP/2 + Early Hints, SSL Labs Grade B.

---

## 4. Prioritized Hardening Checklist

### P1 — This week (Critical)
- [ ] **SPF:** `v=spf1 -all` (domain sends no mail)
- [ ] **DMARC:** `_dmarc` TXT `v=DMARC1; p=reject; rua=mailto:...` (hard fail + reporting)
- [ ] **Null MX** (RFC 7505): `0 .` to formally declare "no mail"

### P2 — This month (High)
- [ ] **CSP:** `default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'` — deploy as Report-Only first
- [ ] **Headers:** `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, minimal `Permissions-Policy`
- [ ] **Lock `/go/play`:** fixed allowlist destination, no user-controlled URL params, `rel="noopener noreferrer"`
- [ ] **Platform accounts:** enforce MFA + least-privilege tokens on Cloudflare and Vercel

### P3 — Next quarter (Medium)
- [ ] **HSTS:** add `includeSubDomains` (add `preload` only after all subdomains are HTTPS-safe)
- [ ] **Content accuracy:** correct RTP claim (98% → 96%), publish truthful affiliate disclosure (resolves "not affiliated" vs "official presentation" contradiction)
- [ ] **Brand monitoring:** track impersonation cluster; file registrar/app-store takedowns
- [ ] **Fix hygiene:** malformed contact email (`contact@www.` → `contact@`), remove stale robots.txt entries (`/api/*`, `/pages/condition-utilisation` now 404)

### P4 — Backlog (Low)
- [ ] **CAA record** limiting issuance to Google Trust Services / Let's Encrypt
- [ ] Remove `x-powered-by` header (Next.js `poweredByHeader: false`)
- [ ] Refresh robots.txt allow-crawl policy for SEO bots if traffic matters

---

## 5. Proportionality Note

The application has **no authentication, no database, and no user data**. The highest-value controls therefore protect **trust and integrity** — email anti-spoofing (P1), framing protection, redirect integrity, and platform-account security (P2) — rather than app-layer controls like heavy WAF rulesets or secrets management, which would be disproportionate here.

---

## 6. Evidence Sources

| Item | Source |
|------|--------|
| DNS (A/AAAA/NS/MX/TXT/CAA) | https://dns.google/resolve?name=chicken-road2.app&type=A |
| Certificate transparency | https://api.certspotter.com/v1/issuances?domain=chicken-road2.app&include_subdomains=true&expand=dns_names |
| Hosting/AS | https://ipinfo.io/104.21.38.193/json |
| TLS grade | https://api.ssllabs.com/api/v3/analyze?host=chicken-road2.app |
| WHOIS | https://www.whois.com/whois/chicken-road2.app |
| Archive history | https://web.archive.org/cdx/search/cdx?url=chicken-road2.app&output=json&limit=40&collapse=timestamp:6 |
