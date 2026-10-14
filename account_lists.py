#!/usr/bin/env python3
"""
Cross-reference feed orgs against the partner / rep account lists folder.

  python account_lists.py index                 # (re)build account_index.json.gz from every xlsx/csv
  python account_lists.py match docs/signals.json  # -> account_matches.json (PRIVATE: rep names, partners)

Every sheet is scanned. Name columns are recognized by header (account, company,
customer, name, acct, L0/L1AccountName, DynamicsAccountName, buying account);
website/domain columns by header or by value. Sheets without a header row get a
fallback: every short text cell that is not an email, URL, number or date is a
candidate name. Matching is strict (same rules as the domain matcher): exact
domain, or the org's distinctive words equal to / contained in the list entry.
"""
import csv, glob, gzip, json, os, re, sys, datetime as dt
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from breach_feed import norm, sig, strong_sig, name_variants, clean_domain

HERE = os.path.dirname(os.path.abspath(__file__))
LISTS_DIR = os.environ.get("ACCOUNT_LISTS_DIR", r"C:\Users\ladams1\Radius Channel Management\Cole Campbell - Account List Sample Data")
INDEX = os.path.join(HERE, "account_index.json.gz")
MATCHES = os.path.join(HERE, "account_matches.json")

NAME_HDR = re.compile(r"(account|company|customer|acct|name|l0accountname|l1accountname|dynamicsaccountname|buying)", re.I)
NOT_NAME_HDR = re.compile(r"(contact|first|last|rep\b|owner|\bae\b|partner|email|phone|city|state|country|zip|street|address|id\b|checksum|modified|website|domain|url|linkedin|zoominfo|title|role|notes?$|industry|type|segment|tier|status|stage|rank|quarter|territory|manager|specialist|cm\b|isg|idg|number|employees|revenue)", re.I)
WEB_HDR = re.compile(r"(website|domain|url|web)", re.I)
PEOPLE_HDR = re.compile(r"(rep\b|rep |owner|\bae\b|partner|contact|manager|specialist|cm\b|cf ae|cloudflare ae|druva rep|tanium rep|client manager|field rep|current rep|channel|sold|mapped|solutions|notes|email|status|type|tier|stage|relationship)", re.I)
EMAIL_RX = re.compile(r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$", re.I)
URL_RX = re.compile(r"(?:https?://)?(?:www\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)", re.I)

def _s(v):
    if v is None: return ""
    if isinstance(v, float) and v.is_integer(): v = int(v)
    return str(v).strip()

def _is_namey(s):
    if not (3 <= len(s) <= 70) or len(s.split()) > 9: return False
    if EMAIL_RX.match(s) or re.match(r"^(https?://|www\.)", s, re.I): return False
    if re.fullmatch(r"[\d\s.,$%/:-]+", s): return False
    if re.match(r"^\d{1,4}[/-]\d{1,2}[/-]\d{2,4}", s): return False
    return bool(re.search(r"[A-Za-z]{2}", s))

def iter_sheets():
    for f in sorted(glob.glob(os.path.join(LISTS_DIR, "**", "*"), recursive=True)):
        if os.path.basename(f).startswith(("~$", ".")) or os.path.isdir(f): continue
        ext = f.lower().rsplit(".", 1)[-1]
        rel = os.path.relpath(f, LISTS_DIR)
        if ext in ("xlsx", "xlsm"):
            try:
                import openpyxl
                wb = openpyxl.load_workbook(f, read_only=True, data_only=True)
            except Exception as e:
                print(f"  skip {rel}: {e}", file=sys.stderr); continue
            for ws in wb.worksheets:
                yield rel, ws.title, (tuple(_s(c) for c in row) for row in ws.iter_rows(values_only=True))
        elif ext == "csv":
            def rows(path=f):
                with open(path, encoding="utf-8", errors="ignore", newline="") as fh:
                    for row in csv.reader(fh):
                        yield tuple(_s(c) for c in row)
            yield rel, "csv", rows()

def build_index():
    idx_name, idx_dom = {}, {}
    n_sheets = n_rows = 0
    for rel, sheet, rows in iter_sheets():
        n_sheets += 1
        header, name_cols, web_cols, hdr_row = None, [], [], 0
        big = False
        for rno, row in enumerate(rows, 1):
            if not any(row): continue
            if header is None:
                texts = [c for c in row if c]
                # a header row: mostly short text, at least one name-ish header
                if rno <= 6 and len(texts) >= 2 and any(NAME_HDR.search(c) and not NOT_NAME_HDR.search(c) for c in texts) and all(len(c) <= 60 for c in texts):
                    header = list(row); hdr_row = rno
                    name_cols = [i for i, h in enumerate(header) if h and NAME_HDR.search(h) and not NOT_NAME_HDR.search(h)]
                    web_cols = [i for i, h in enumerate(header) if h and WEB_HDR.search(h)]
                    continue
                if rno > 6 and header is None:
                    header = []   # headerless sheet: fallback mode
            n_rows += 1
            if n_rows and rno > 200000: big = True
            rec_cells = {}
            if header:
                for i, c in enumerate(row):
                    if c and i < len(header) and header[i]:
                        rec_cells[header[i][:40]] = c[:120]
            else:
                for i, c in enumerate(row):
                    if c: rec_cells[f"col{i+1}"] = c[:120]
            if not rec_cells: continue
            rec = {"f": rel, "s": sheet, "r": rno, "c": dict(list(rec_cells.items())[:14])}
            names = [row[i] for i in name_cols if i < len(row) and row[i]] if header else [c for c in row if c and _is_namey(c)]
            if header and not names and not big:
                names = [c for c in row if c and _is_namey(c)][:2]
            for nm in names:
                k = norm(nm)
                if len(k) >= 3:
                    idx_name.setdefault(k, []).append(rec) if len(idx_name.get(k, [])) < 6 else None
            doms = [row[i] for i in web_cols if i < len(row) and row[i]] if header else []
            if not header or not big:
                doms += [c for c in row if c and (EMAIL_RX.match(c) or re.match(r"^(https?://|www\.)", c, re.I))]
            for dv in doms:
                m = URL_RX.search(dv.split("@")[-1])
                d = clean_domain(m.group(1).lower()) if m else ""
                if d and not re.search(r"(gmail|yahoo|outlook|hotmail|linkedin|zoominfo|crossbeam)\.", d):
                    idx_dom.setdefault(d, []).append(rec) if len(idx_dom.get(d, [])) < 6 else None
        print(f"  {rel} / {sheet}: header={'yes' if header else 'no'} names={len(name_cols)} web={len(web_cols)}", file=sys.stderr)
    out = {"built": dt.date.today().isoformat(), "dir": LISTS_DIR, "sheets": n_sheets, "rows": n_rows, "names": idx_name, "domains": idx_dom}
    with gzip.open(INDEX, "wt", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False)
    print(f"index: {n_sheets} sheets, {n_rows} rows, {len(idx_name)} names, {len(idx_dom)} domains -> {INDEX}")

def _people(cells):
    """the columns a salesperson cares about, as 'Header: value' pairs"""
    out = []
    for h, v in cells.items():
        if PEOPLE_HDR.search(h) or EMAIL_RX.match(v):
            out.append(f"{h.strip()}: {v}")
    return out

def match(signals_path):
    with gzip.open(INDEX, "rt", encoding="utf-8") as fh:
        idx = json.load(fh)
    names, doms = idx["names"], idx["domains"]
    sigmap = {}
    for k in names:
        s = frozenset(sig(k))
        if s: sigmap.setdefault(s, []).append(k)
    s_ = json.load(open(signals_path, encoding="utf-8"))["signals"]
    out, n = {}, 0
    for r in s_:
        hits = []
        if r["domain"] and r["domain"] in doms:
            hits += [("domain", h) for h in doms[r["domain"]]]
        k = norm(r["org"]); so = frozenset(strong_sig(r["org"]))
        if k in names:
            hits += [("exact name", h) for h in names[k]]
        elif so and len(so) >= 1:
            for cand in sigmap.get(so, []):
                hits += [("name words" if len(so) >= 2 else "single distinctive word", h) for h in names[cand]]
            if len(so) >= 2 and not hits:
                for s2, cands in sigmap.items():
                    if so < s2 and len(s2) <= len(so) + 1:
                        for cand in cands: hits += [("name contained", h) for h in names[cand]]
        seen, uniq = set(), []
        for how, h in hits:
            key = (h["f"], h["s"], h["r"])
            if key in seen: continue
            seen.add(key); uniq.append({"how": how, "file": h["f"], "sheet": h["s"], "row": h["r"], "cells": h["c"], "people": _people(h["c"])})
        if uniq:
            n += 1
            out[r["domain"] or k] = {"org": r["org"], "hits": uniq[:8], "summary": " || ".join(
                f"{os.path.basename(h['file'])} / {h['sheet']} row {h['row']} ({h['how']}): " + ("; ".join(h["people"]) or "listed, no rep columns") for h in uniq[:4])[:900]}
    json.dump(out, open(MATCHES, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    print(f"account-list matches: {n} of {len(s_)} orgs -> {MATCHES}")
    for k, v in list(out.items())[:40]:
        print(f"  {v['org'][:40]:40} | {v['summary'][:200]}")

if __name__ == "__main__":
    if sys.argv[1] == "index": build_index()
    elif sys.argv[1] == "match": match(sys.argv[2])
