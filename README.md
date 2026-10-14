# breach-signals

Daily feed of US/Canada organizations with a recently disclosed security incident, built from mandatory government breach filings, ransomware leak-site claims, verified credential dumps and plaintiff-firm investigation posts. Intended as a sales trigger feed for Radius Channels (Illumio / RSA / DigiCert) and as an input to POE.

- Site: `docs/index.html` (GitHub Pages)
- Machine feed: `docs/signals.json`, `docs/signals.csv`
- Refresh: `.github/workflows/refresh.yml`, daily 11:15 UTC, 30-day window
- Script: `breach_feed.py` (stdlib only). `python breach_feed.py --days 30 --json docs/signals.json --out docs/signals.csv`
- Domain cache: `domains.json` (Clearbit autocomplete, then DuckDuckGo; blocklisted aggregators)

## signals.json shape

```
{ generated_utc, window_days, tiers, sources[], manual_sources[], count,
  signals: [ { tier, reported, org, domain, domain_source, country, state, sector, affected,
               breach_date, incident_type, lead_with, product_fit, confidence, reported_to, source, detail,
               url, letter_url, evidence_url, press_url, verify_url } ] }
```

`confidence`: `confirmed` (the org filed with a regulator), `corroborated` (leak-site claim plus an independent source), `unverified` (leak-site claim only), `verified dump` (HIBP), `reported` (plaintiff firm). For tier-2 rows `evidence_url` is ransomware.live's screenshot of the gang's post, `url` the ransomware.live record, `detail` carries the gang name, claimed data size, ransom and the Tor claim URL, and `verify_url` is a prebuilt Google News check.

`tier` 1 = mandatory government filing (CA, WA, VT, OR AG), 2 = leak-site claim (ransomware.live) or HIBP-verified dump, 3 = plaintiff-firm investigation after a consumer notice. News headlines are used only to corroborate an org row and are never rows themselves.

Set repository secret `RWL_PRO_KEY` (free business key from ransomware.live/api) before relying on the leak-site rows; the public v2 endpoint is personal-use only.
