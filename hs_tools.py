#!/usr/bin/env python3
"""
HubSpot enrichment helpers for the breach feed.

The HubSpot access on this workstation is the HubSpot MCP connector (no API
token on disk), so the queries are run by the operator through the connector
and the answers are saved to hubspot_matches.json, which breach_feed.py merges
on every run. This file only (a) prints the SQL batches to run and (b) folds
connector answers into hubspot_matches.json.

  python hs_tools.py batches docs/signals.json        # prints SQL, 20 conditions each
  python hs_tools.py ingest results.json              # results.json = list of connector rows

hubspot_matches.json shape (keyed by normalized org name OR domain):
  { key: { company_id, company, domain, owner, industry, state, employees, revenue,
           deals, contacts, modified, deal_list: [ {name, stage, amount, close, reseller, vendor} ] } }
"""
import json, re, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from breach_feed import norm, sig, name_variants, domain_matches, GENERIC

HERE = os.path.dirname(os.path.abspath(__file__))
MATCHES = os.path.join(HERE, "hubspot_matches.json")
PROPS = "hs_object_id, name, domain, hubspot_owner_id, industry, state, numberofemployees, annualrevenue, num_associated_deals, num_associated_contacts, hs_lastmodifieddate, lifecyclestage"
DEAL_PROPS = "hs_object_id, dealname, dealstage, pipeline, amount, closedate, hubspot_owner_id"   # cross-object columns silently empty the result
VENDORS = {"lenovo", "tanium", "druva", "cloudflare", "illumio", "rsa", "digicert", "tenable", "zscaler", "crowdstrike", "okta", "proofpoint", "palo alto", "fortinet", "netskope", "rubrik", "cohesity", "veeam", "nutanix", "vmware", "hpe", "dell", "cisco", "arctic wolf", "sentinelone", "wiz", "varonis"}

def chunks(xs, n=20):
    for i in range(0, len(xs), n):
        yield xs[i:i + n]

def deal_token(org):
    """the EndCustomer token as it appears in Reseller_EndCustomer_Vendor deal names (spaces kept)"""
    from breach_feed import strong_sig
    base = name_variants(org)[0].replace("'", "''")
    if not strong_sig(org):
        return ""
    return base[:30]

def batches(signals_path):
    s = json.load(open(signals_path, encoding="utf-8"))["signals"]
    try:
        done = json.load(open(MATCHES, encoding="utf-8"))
    except Exception:
        done = {}
    doms = sorted({r["domain"] for r in s if r["domain"] and r["domain"] not in done})
    names = [r["org"] for r in s if not r["domain"] and norm(r["org"]) not in done]
    print(f"-- {len(doms)} domains, {len(names)} names without domain, {len(s)} orgs total\n")
    for i, c in enumerate(chunks(doms)):
        print(f"-- DOMAINS {i+1}\nSELECT {PROPS} FROM COMPANY WHERE " + " OR ".join(f"domain = '{d}'" for d in c) + "\n")
    for i, c in enumerate(chunks(names)):
        print(f"-- NAMES {i+1}\nSELECT {PROPS} FROM COMPANY WHERE " + " OR ".join(f"name LIKE '%{name_variants(n)[0][:40].replace(chr(39), chr(39)*2)}%'" for n in c) + "\n")
    toks = sorted({deal_token(r["org"]) for r in s if len(deal_token(r["org"])) >= 5})
    for i, c in enumerate(chunks(toks)):
        print(f"-- DEALNAMES {i+1}\nSELECT {DEAL_PROPS} FROM DEAL WHERE " + " OR ".join(f"dealname LIKE '%{t}%'" for t in c) + "\n")

COMPACT = {"n": "name", "d": "domain", "id": "hs_object_id", "o": "hubspot_owner_id_formatted", "ind": "industry", "st": "state",
           "emp": "numberofemployees", "rev": "annualrevenue", "deals": "num_associated_deals", "cts": "num_associated_contacts",
           "mod": "hs_lastmodifieddate_iso", "lc": "lifecyclestage",
           "dn": "dealname", "stg": "dealstage", "amt": "amount", "cl": "closedate_iso", "cd": "COMPANY.domain", "cn": "COMPANY.name"}

def _row(obj):
    p = dict(obj.get("properties", obj))
    for k, v in list(p.items()):
        if k in COMPACT and COMPACT[k] not in p:
            p[COMPACT[k]] = v
    return p

def ingest(results_path, signals_path):
    """results.json: list of connector rows (each a dict with 'properties' or flat).
    Company rows are matched to feed orgs by exact domain or by strict name match;
    deal rows are attached by COMPANY.domain or by the EndCustomer token."""
    rows = json.load(open(results_path, encoding="utf-8"))
    s = json.load(open(signals_path, encoding="utf-8"))["signals"]
    try:
        m = json.load(open(MATCHES, encoding="utf-8"))
    except Exception:
        m = {}
    by_dom = {r["domain"]: r for r in s if r["domain"]}
    n_c = n_d = 0
    for raw in rows:
        p = _row(raw)
        if "dealname" in p:
            continue
        dom = (p.get("domain") or "").lower().strip().replace("www.", "")
        target = None
        if p.get("match_org"):   # operator-verified match by name
            target = next((r for r in s if r["org"] == p["match_org"] or norm(r["org"]) == norm(p["match_org"]) or norm(p["match_org"]) in norm(r["org"])), None)
        if not target and dom and dom in by_dom:
            target = by_dom[dom]
        elif not target:
            for r in s:
                if domain_matches(dom or "x.com", p.get("name", ""), r["org"]) and sig(p.get("name", "")) and sig(p.get("name", "")) <= sig(r["org"]) | {"inc", "llc"} and sig(r["org"]) & sig(p.get("name", "")):
                    target = r; break
        if not target:
            continue
        key = target["domain"] or norm(target["org"])
        m[key] = {
            "company_id": p.get("hs_object_id", ""), "company": p.get("name", ""), "domain": dom,
            "owner": p.get("hubspot_owner_id_formatted") or p.get("hubspot_owner_id", ""),
            "industry": p.get("industry", ""), "state": p.get("state", ""), "employees": p.get("numberofemployees", ""),
            "revenue": p.get("annualrevenue", ""), "deals": p.get("num_associated_deals", "0") or "0",
            "contacts": p.get("num_associated_contacts", "0") or "0",
            "modified": (p.get("hs_lastmodifieddate_iso") or "")[:10], "lifecycle": p.get("lifecyclestage", ""),
            "deal_list": m.get(key, {}).get("deal_list", []),
        }
        n_c += 1
    for raw in rows:
        p = _row(raw)
        if "dealname" not in p:
            continue
        name = p["dealname"]; parts = name.split("_")
        reseller = parts[0].strip() if len(parts) >= 2 else ""
        endcust = parts[1].strip() if len(parts) >= 2 else name
        vendor = next((x.strip() for x in parts[2:] if x.strip().lower() in VENDORS), "") if len(parts) >= 3 else ""
        if not vendor:
            vendor = p.get("pipeline_formatted", "") if p.get("pipeline_formatted", "").lower() in VENDORS else ""
        cdom = (p.get("COMPANY.domain") or p.get("company_domain") or "").lower()
        target = by_dom.get(cdom)
        mo = p.get("mo") or p.get("match_org")
        if not target and mo:   # operator-verified end customer
            mk = norm(mo).replace(" ", "")
            target = next((r for r in s if mk and (mk == norm(r["org"]).replace(" ", "") or mk in norm(r["org"]).replace(" ", ""))), None)
        if not target and endcust:
            ec = norm(endcust).replace(" ", "")
            best = None
            for r in s:
                on = norm(r["org"]).replace(" ", "")
                if not ec or not on: continue
                if ec == on or (len(ec) >= 5 and (on.startswith(ec) or ec.startswith(on) or (len(ec) >= 8 and ec in on))):
                    if best is None or len(on) < len(norm(best["org"]).replace(" ", "")):
                        best = r
            target = best
        if not target:
            continue
        key = target["domain"] or norm(target["org"])
        m.setdefault(key, {"company_id": "", "company": "", "domain": target["domain"], "owner": "", "industry": "", "state": "", "employees": "", "revenue": "", "deals": "0", "contacts": "0", "modified": "", "lifecycle": "", "deal_list": []})
        d = {"id": p.get("hs_object_id") or name, "name": name, "stage": p.get("dealstage_formatted") or p.get("stg") or p.get("dealstage", ""), "amount": p.get("amount_formatted") or p.get("amount", ""),
             "close": (p.get("closedate_iso") or p.get("cl") or p.get("closedate", ""))[:10], "owner": p.get("hubspot_owner_id_formatted") or p.get("o") or "", "reseller": reseller, "vendor": vendor}
        if d["id"] not in {x.get("id") for x in m[key]["deal_list"]}:
            m[key]["deal_list"].append(d); n_d += 1
    json.dump(m, open(MATCHES, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    print(f"companies matched: {n_c}   deals attached: {n_d}   total keys: {len(m)}")

if __name__ == "__main__":
    if sys.argv[1] == "batches":
        batches(sys.argv[2])
    elif sys.argv[1] == "ingest":
        ingest(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else os.path.join(HERE, "docs", "signals.json"))
