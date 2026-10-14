#!/usr/bin/env python3
"""
Radius breach-signal feed.

Pulls recently disclosed security incidents at US/Canada organizations from
public, machine-readable sources and writes one de-duplicated CSV so the
channel team can hand partners a "this customer just had an incident" list.

Sources automated here (all free, no login):
  state_ca  California AG breach list        (HTML table, letters attached)
  state_wa  Washington AG breach list        (HTML table, letters attached)
  state_vt  Vermont AG breach summary        (HTML table)
  state_or  Oregon DOJ breach list           (HTML table)
  state_de  Delaware DOJ breach list         (HTML table, letters attached)
  state_hi  Hawaii OCP breach notices        (HTML table, letters attached)
  hibp      HaveIBeenPwned breach catalog    (JSON, no key needed)
  rwl       ransomware.live leak-site claims (JSON; set RWL_PRO_KEY for the
            business-licensed PRO API, otherwise v2 is used which the site
            labels personal-use only)
  rss_sb    Strauss Borrelli investigations  (RSS, one post per notified org)
  rss_lc    Lynch Carpenter investigations   (RSS)
  rss_dbn   DataBreaches.net                  (RSS)
  gnews_us  Google News "data breach" (US)   (RSS)
  gnews_ca  Google News "data breach" (CA)   (RSS)

Manual sources (JS portals or login walls) are listed in MANUAL_SOURCES and
printed at the end of every run so nobody forgets them.

Usage:
  python breach_feed.py                 # last 14 days -> breach_signals.csv
  python breach_feed.py --days 30
  python breach_feed.py --out C:/path/file.csv --only state_ca,rwl

Stdlib only. Python 3.9+.
"""
import argparse, csv, datetime as dt, html, json, os, re, sys, time, urllib.request, urllib.error
import xml.etree.ElementTree as ET
import urllib.parse

UA = "Mozilla/5.0 (compatible; RadiusBreachFeed/0.1; +mailto:ladams@radiuschannels.com)"
TODAY = dt.date.today()

# ----------------------------------------------------------------------------
# product-fit tagging. Keyword -> Radius portfolio line. Crude but useful for
# routing the lead to the right partner conversation.
# ----------------------------------------------------------------------------
FIT_RULES = [
    ("Illumio",  r"ransomware|encrypt|lateral|leak site|extort|lockbit|akira|qilin|play|ransomhub|inc ransom|safepay|medusa|clop|blackbasta|black basta|hunters|dragonforce|lynx|sinobi|devman"),
    ("RSA",      r"credential|phish|password|account takeover|unauthori[sz]ed access|email account|mfa|multi-factor|business email|compromised account|social engineer|vishing|session|okta|identity"),
    ("DigiCert", r"certificate|tls|ssl|dns|domain hijack|spoof|code.?signing|pki|typosquat|look-?alike domain"),
]

def product_fit(text):
    t = (text or "").lower()
    hits = [name for name, rx in FIT_RULES if re.search(rx, t)]
    if not hits:
        it = incident_type(t)
        if it in ("network intrusion", "third-party / vendor incident"):
            hits = ["Illumio", "RSA"]
    return "; ".join(hits) if hits else "Illumio; RSA (unclassified incident)"

# ----------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------
def get(url, timeout=60, headers=None, retries=2):
    h = {"User-Agent": UA, "Accept": "*/*"}
    if headers: h.update(headers)
    last = None
    for i in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers=h)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read().decode("utf-8", "ignore")
        except Exception as e:  # noqa
            last = e
            time.sleep(2 + 3 * i)
    raise last

def strip(s):
    s = re.sub(r"<[^>]+>", " ", s or "")
    return re.sub(r"\s+", " ", html.unescape(s)).strip()

DATE_PATTERNS = [
    (r"(\d{1,2})[/\-\.](\d{1,2})[/\-\.](\d{4})", "mdy"),
    (r"(\d{4})[/\-\.](\d{1,2})[/\-\.](\d{1,2})", "ymd"),
]
def parse_date(s):
    """Return the FIRST date found in s as a date, else None."""
    s = s or ""
    for rx, order in DATE_PATTERNS:
        m = re.search(rx, s)
        if m:
            a, b, c = (int(x) for x in m.groups())
            try:
                return dt.date(c, a, b) if order == "mdy" else dt.date(a, b, c)
            except ValueError:
                continue
    try:
        import email.utils
        d = email.utils.parsedate_to_datetime(s.strip())
        if d:
            return d.date()
    except Exception:
        pass
    return None

def table_rows(page):
    """Yield (cells_text, cells_href) for every <tr> in page."""
    for tr in re.findall(r"<tr[^>]*>(.*?)</tr>", page, re.S):
        cells = re.findall(r"<t[dh][^>]*>(.*?)</t[dh]>", tr, re.S)
        if not cells:
            continue
        texts = [strip(c) for c in cells]
        hrefs = []
        for c in cells:
            m = re.search(r'href="([^"]+)"', c)
            hrefs.append(html.unescape(m.group(1)) if m else "")
        yield texts, hrefs

def absolute(base, href):
    if not href or href.startswith("http"):
        return href
    from urllib.parse import urljoin
    return urljoin(base, href)

REPORTED_TO = {
    "state_ca": "California Attorney General (Civ. Code 1798.82 filing)",
    "state_wa": "Washington Attorney General (RCW 19.255 filing)",
    "state_vt": "Vermont Attorney General (9 V.S.A. 2435 filing)",
    "state_or": "Oregon Dept of Justice (ORS 646A.604 filing)",
    "state_de": "Delaware Dept of Justice filing",
    "state_hi": "Hawaii Office of Consumer Protection filing",
    "hibp": "HaveIBeenPwned breach catalog (credential dump verified by HIBP)",
    "rwl": "Ransomware group leak site (claim, via ransomware.live)",
    "rss_sb": "Strauss Borrelli PLLC class-action investigation (follows a consumer notice)",
    "rss_lc": "Lynch Carpenter LLP class-action investigation (follows a consumer notice)",
    "rss_dbn": "DataBreaches.net reporting",
    "gnews_us": "News (Google News US)", "gnews_ca": "News (Google News Canada)",
}

def rec(source, org, reported, breach_date="", affected="", country="US", state="", sector="", detail="", url="", domain="", letter_url=""):
    detail = (detail or "")[:400]
    return {
        "source": source, "reported_to": REPORTED_TO.get(source, source), "org": org.strip(), "domain": domain,
        "reported": reported.isoformat() if isinstance(reported, dt.date) else (reported or ""),
        "breach_date": breach_date, "affected": affected, "country": country, "state": state,
        "sector": sector, "detail": detail, "product_fit": product_fit(f"{sector} {detail} {org}"), "url": url,
        "letter_url": letter_url,
    }

# ----------------------------------------------------------------------------
# state AG tables
# ----------------------------------------------------------------------------
def state_ca(days):
    base = "https://oag.ca.gov/privacy/databreach/list"
    out = []
    for page in range(0, 6):
        html_ = get(f"{base}?page={page}")
        got = 0
        for t, h in table_rows(html_):
            if len(t) < 3 or t[0] == "Organization Name":
                continue
            rep = parse_date(t[2])
            if not rep: continue
            got += 1
            if (TODAY - rep).days > days:
                return out
            report = absolute(base, h[0])
            letter = ""
            try:  # the report page links the redacted consumer notice letter
                m = re.search(r'field-name-field-sb24-attachment.*?href="([^"]+)"', get(report, timeout=30, retries=0), re.S)
                letter = html.unescape(m.group(1)) if m else ""
            except Exception:
                pass
            out.append(rec("state_ca", t[0], rep, t[1], "", "US", "CA", "",
                           "Breach notice filed with the California AG; consumer letter attached.", report, "", letter))
        if got == 0:
            break
    return out

def state_wa(days):
    base = "https://www.atg.wa.gov/data-breach-notifications"
    out = []
    for page in range(0, 6):
        html_ = get(f"{base}?page={page}")
        got = 0
        for t, h in table_rows(html_):
            if len(t) < 5 or t[0] == "Date Reported":
                continue
            rep = parse_date(t[0])
            if not rep: continue
            got += 1
            if (TODAY - rep).days > days:
                return out
            out.append(rec("state_wa", t[1], rep, t[2], t[3], "US", "WA", "", "Data compromised: " + t[4], base, "", absolute(base, h[1])))
        if got == 0:
            break
    return out

def state_vt(days):
    base = "https://ago.vermont.gov/categories/security-breach-notices"
    out = []
    for t, h in table_rows(get(base)):
        if len(t) < 5 or t[0].startswith("Date Reported"):
            continue
        rep = parse_date(t[0])
        if not rep or (TODAY - rep).days > days: continue
        out.append(rec("state_vt", t[1], rep, "", t[3], "US", "VT", t[2], "Data compromised: " + t[4], base))
    return out

def state_or(days):
    base = "https://justice.oregon.gov/consumer/DataBreach/"
    out = []
    for t, h in table_rows(get(base)):
        if len(t) < 6 or t[0] == "Organization":
            continue
        rep = parse_date(t[1])
        if not rep or (TODAY - rep).days > days: continue
        out.append(rec("state_or", t[0], rep, t[2], t[5], "US", "OR", "", f"Discovered {t[3]}; consumer notice sent {t[4]}.", absolute(base, h[0]) or base))
    return out

def state_de(days):
    base = "https://attorneygeneral.delaware.gov/fraud/cpu/securitybreachnotification/database/"
    out = []
    for t, h in table_rows(get(base)):
        if len(t) < 4 or t[0] == "Organization Name":
            continue
        rep = parse_date(t[2])
        if not rep or (TODAY - rep).days > days: continue
        link = h[4] if len(h) > 4 and h[4] else base
        out.append(rec("state_de", t[0], rep, t[1], t[3], "US", "DE", "", "Breach notice filed with Delaware DOJ.", base, "", absolute(base, link)))
    return out

def state_hi(days):
    base = "https://cca.hawaii.gov/ocp/notices/security-breach/"
    out = []
    for t, h in table_rows(get(base)):
        if len(t) < 5 or t[0] == "Date Notified":
            continue
        rep = parse_date(t[0])
        if not rep or (TODAY - rep).days > days: continue
        link = h[5] if len(h) > 5 and h[5] else base
        out.append(rec("state_hi", t[2], rep, "", t[4], "US", "HI", "", "Breach type: " + t[3], base, "", absolute(base, link)))
    return out

# ----------------------------------------------------------------------------
# APIs
# ----------------------------------------------------------------------------
def hibp(days):
    data = json.loads(get("https://haveibeenpwned.com/api/v3/breaches", headers={"Accept": "application/json"}))
    out = []
    for b in data:
        added = parse_date(b.get("AddedDate", ""))
        if not added or (TODAY - added).days > days: continue
        out.append(rec("hibp", b["Title"], added, b.get("BreachDate", ""), str(b.get("PwnCount", "")), "?", "",
                       "", strip(b.get("Description", "")), f"https://haveibeenpwned.com/Breach/{b['Name']}", b.get("Domain", "")))
    return out

def rwl(days):
    key = os.environ.get("RWL_PRO_KEY")
    out = []
    if key:
        url = "https://api-pro.ransomware.live/victims/recent?order=discovered"
        raw = get(url, headers={"X-API-KEY": key, "Accept": "application/json"})
        data = json.loads(raw)
        if isinstance(data, dict):
            data = data.get("victims") or data.get("data") or []
    else:
        print("  [rwl] RWL_PRO_KEY not set: using v2 public endpoint. ransomware.live labels v2 personal-use only; "
              "request the free PRO key at https://www.ransomware.live/api before using this at work.", file=sys.stderr)
        data = json.loads(get("https://api.ransomware.live/v2/recentvictims", headers={"Accept": "application/json"}))
    for v in data:
        if v.get("country") not in ("US", "CA"):
            continue
        dom = clean_domain(v.get("domain", ""))
        if dom and re.search(r"\.(ua|ru|uk|de|fr|jp|au|nz|in|br|za|it|es|nl|se|ch|ie|kr|sg|mx|ar|cl|cn|tw|hk|il|ae|sa|pl|cz|at|be|dk|no|fi|pt|tr|id|th|ph|my|vn|pk)$", dom):
            continue  # ransomware.live mis-tagged the country
        disc = parse_date(v.get("discovered") or v.get("attackdate") or "")
        if not disc or (TODAY - disc).days > days: continue
        name = v.get("victim") or v.get("post_title") or v.get("domain") or ""
        out.append(rec("rwl", name, disc, (v.get("attackdate") or "")[:10], "", v["country"], "",
                       v.get("activity", ""), f"leak-site claim by {v.get('group','')}: {strip(v.get('description',''))}",
                       v.get("url") or v.get("claim_url") or "", dom))
    return out

# ----------------------------------------------------------------------------
# RSS
# ----------------------------------------------------------------------------
def rss(source, url, days, title_rx=None, country="US", org_from_title=None):
    root = ET.fromstring(get(url).encode("utf-8", "ignore"))
    out = []
    for item in root.iter("item"):
        title = strip(item.findtext("title", ""))
        link = (item.findtext("link") or "").strip()
        pub = parse_date(item.findtext("pubDate", ""))
        desc = strip(item.findtext("description", ""))
        if title_rx and not re.search(title_rx, title, re.I):
            continue
        if not pub or (TODAY - pub).days > days: continue
        org = org_from_title(title) if org_from_title else title
        out.append(rec(source, org, pub, "", "", country, "", "", f"{title} :: {desc}"[:300], link))
    return out

def _lawfirm_org(title):
    return re.sub(r"\s*(data breach|data security|cyber(security)? incident).*$", "", title, flags=re.I).strip()

def rss_sb(days):  return rss("rss_sb", "https://straussborrelli.com/feed/", days, r"data breach|data security|cyber", "US", _lawfirm_org)
def rss_lc(days):  return rss("rss_lc", "https://lynchcarpenter.com/feed/", days, r"data breach|data security|cyber", "US", _lawfirm_org)
def rss_dbn(days): return rss("rss_dbn", "https://databreaches.net/feed/", days, None, "?")

GN = "https://news.google.com/rss/search?q={q}&hl=en-{gl}&gl={gl}&ceid={gl}:en"
Q = '("data breach" OR ransomware OR "cyberattack" OR "cyber attack" OR "cyber incident" OR "security incident") when:{d}d'
def gnews_us(days): return rss("gnews_us", GN.format(q=urllib.parse.quote(Q.format(d=min(days, 30))), gl="US"), days, None, "US", lambda t: t.split(" - ")[0])
def gnews_ca(days): return rss("gnews_ca", GN.format(q=urllib.parse.quote(Q.format(d=min(days, 30))), gl="CA"), days, None, "CA", lambda t: t.split(" - ")[0])


SOURCES = {
    "state_ca": state_ca, "state_wa": state_wa, "state_vt": state_vt, "state_or": state_or,
    "state_de": state_de, "state_hi": state_hi, "hibp": hibp, "rwl": rwl,
    "rss_sb": rss_sb, "rss_lc": rss_lc, "rss_dbn": rss_dbn, "gnews_us": gnews_us, "gnews_ca": gnews_ca,
}

MANUAL_SOURCES = [
    ("HHS OCR breach portal (health, 500+ individuals; CSV export button)", "https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf"),
    ("SEC EDGAR full-text: 8-K Item 1.05 material cyber incidents (public cos)", 'https://www.sec.gov/edgar/search/#/q=%22Item%201.05%22&dateRange=custom&forms=8-K'),
    ("Texas AG breach report portal (250+ residents, JS)", "https://oag.my.site.com/datasecuritybreachreport/apex/DataSecurityReportsPage"),
    ("Maine AG breach notices (moved to AccessGov portal)", "https://www.maine.gov/ag/consumer-protection/data-security-breaches"),
    ("Nebraska AG public breach search (AccessGov)", "https://ne.accessgov.com/ago/Forms/Page/ago/85cc7822-5ca7-4eb1-ba3a-e54a5f45eadb/6e853c78-d850-42c6-9163-59b7688e2632/0"),
    ("Massachusetts OCABR breach reports (annual XLSX; blocks bots)", "https://www.mass.gov/lists/data-breach-reports"),
    ("New Hampshire DOJ security breaches (blocks bots)", "https://www.doj.nh.gov/consumer/security-breaches/"),
    ("Iowa AG security breach notifications", "https://www.iowaattorneygeneral.gov/for-consumers/security-breach-notifications"),
    ("Indiana AG security breaches (PDF list)", "https://www.in.gov/attorneygeneral/consumer-protection-division/id-theft-prevention/security-breaches/"),
    ("Wisconsin DATCP data breaches", "https://datcp.wi.gov/Pages/Programs_Services/DataBreaches.aspx"),
    ("Maryland AG breach notices", "https://www.marylandattorneygeneral.gov/Pages/IdentityTheft/breachnotices.aspx"),
    ("New Jersey NJCCIC breach notifications", "https://www.cyber.nj.gov/threat-center/data-breach-notifications"),
    ("Connecticut AG breach notifications", "https://portal.ct.gov/ag/sections/privacy/data-breach-notifications"),
    ("Canada: no public per-incident registry (OPC/Alberta/Quebec publish stats only); rely on rwl + gnews_ca + rss_dbn", "https://www.priv.gc.ca/en/"),
]

US_STATES = "Alabama Alaska Arizona Arkansas California Colorado Connecticut Delaware Florida Georgia Hawaii Idaho Illinois Indiana Iowa Kansas Kentucky Louisiana Maine Maryland Massachusetts Michigan Minnesota Mississippi Missouri Montana Nebraska Nevada Hampshire Jersey Mexico York Carolina Dakota Ohio Oklahoma Oregon Pennsylvania Rhode Tennessee Texas Utah Vermont Virginia Washington Wisconsin Wyoming".split()
CA_PROV = "Ontario Quebec Québec Alberta Manitoba Saskatchewan Columbia Brunswick Scotia Newfoundland Yukon Nunavut Toronto Vancouver Montreal Calgary Ottawa Edmonton Winnipeg".split()
NA_RX = re.compile(r"\b(U\.?S\.?A?|United States|America[n]?|Canad[ai][a-z]*|federal|county|HIPAA|HHS|FBI|CISA|attorney general|" +
                   "|".join(US_STATES + CA_PROV) + r")\b", re.I)

def north_america(r):
    """True if the row is tied to a US/Canada organization. Government filings and
    rwl rows are already geo-scoped; everything else must name a US/Canada marker."""
    if r["source"].startswith("state_") or r["source"] == "rwl":
        return True
    dom = (r.get("domain") or "").lower()
    if dom.endswith((".us", ".ca", ".gov")):
        return True
    if re.search(r"\.(uk|de|fr|jp|au|nz|in|br|za|it|es|nl|se|ch|ie|kr|sg|mx|ar|cl|ru|cn|tw|hk|il|ae|sa|pl|cz|at|be|dk|no|fi|pt|tr|id|th|ph|my|vn|pk|ng|ke|eg)$", dom):
        return False
    return bool(NA_RX.search(f"{r['org']} {r['detail']} {r['sector']}"))

# ----------------------------------------------------------------------------
# hygiene: clean names, ISO dates, integer counts, incident type
# ----------------------------------------------------------------------------
NAME_NOISE = re.compile(r"\s*(\(?(addendum|supplemental|updated?|amended)[^)]*\)?|data breach (claims? )?investigat\w*( by [a-z &]+)?|data security incident.*|cyber(security)? incident.*)\s*$", re.I)
def clean_org(name):
    n = html.unescape(name or "")
    n = re.sub(r"[“”\"]", "", n)
    n = re.sub(r"\s*\((?:the )?“?[^)]*”?\)\s*$", "", n)          # trailing ("Lockton")
    n = NAME_NOISE.sub("", n)
    n = re.sub(r"\s+", " ", n).strip(" ,;-")
    return n

def iso(s):
    """'9/3/2026' -> 2026-09-03 ; '6/30/2026 - 8/20/2026' -> 2026-06-30/2026-08-20"""
    if not s: return ""
    parts = re.split(r"\s*(?:-|–|—|to|,|and|through|Â­|\?)\s*", s)
    ds = [parse_date(p) for p in parts]
    ds = [d for d in ds if d]
    if not ds: return ""
    if len(ds) == 1 or ds[0] == ds[-1]: return ds[0].isoformat()
    return f"{min(ds).isoformat()}/{max(ds).isoformat()}"

def to_int(s):
    m = re.search(r"\d[\d,]*", str(s or ""))
    return int(m.group(0).replace(",", "")) if m else ""

def incident_type(text):
    t = (text or "").lower()
    if re.search(r"ransom|encrypt|leak.site|extort|lockbit|akira|qilin|\bplay\b|inc ransom|safepay|medusa|clop|black ?basta|dragonforce|interlock|everest", t): return "ransomware / extortion"
    if re.search(r"phish|credential|password|account takeover|e-?mail account|mailbox|mfa|business e-?mail|compromised account|employee.{0,20}account|login", t): return "credential / identity compromise"
    if re.search(r"vendor|service provider|supplier|business associate|third.party (provider|service|software|platform|vendor)|(one of our|a) third.part(y|ies) (that|who|which)|\bmetabase\b|\bsalesforce\b|\bsnowflake\b|\bmoveit\b|\bcitrix\b", t): return "third-party / vendor incident"
    if re.search(r"unauthori[sz]ed (third party|actor|individual|person|party|access)|unusual activity|suspicious activity|network environment|cyber-?security incident|cyber-?attack|intrusion|hack|exfiltrat|accessed (and|or|and/or) (acquired|copied|taken)|gained (remote )?access", t): return "network intrusion"
    if re.search(r"misdirect|inadvertent|human error|misconfig|exposed|mailing error|wrong (recipient|address)", t): return "exposure / error"
    if re.search(r"stolen|theft of|lost (laptop|device)|physical", t): return "device theft / loss"
    if re.search(r"^data compromised:|^breach notice filed", t): return "not stated in filing"
    return "unspecified"

# ----------------------------------------------------------------------------
# domain resolution: Clearbit autocomplete (free, no key) then DuckDuckGo HTML.
# Cached in domains.json next to the script so daily runs only look up new orgs.
# ----------------------------------------------------------------------------
DOMAIN_BLOCK = re.compile(r"(linkedin|facebook|wikipedia|bloomberg|zoominfo|crunchbase|glassdoor|indeed|yelp|bbb\.org|opencorporates|dnb\.com|x\.com|twitter|instagram|youtube|google|duckduckgo|mapquest|yellowpages|manta\.com|buzzfile|sec\.gov|oag\.|\.gov$|classaction|strauss|lynchcarpenter|jdsupra|law360|reuters|bleepingcomputer|securityweek|therecord|databreaches|haveibeenpwned|ransomware\.live|comparably|zippia|signalhire|rocketreach|apollo\.io|lusha|pitchbook|cbinsights|owler|craft\.co|wsj|nytimes|cnn|forbes|prnewswire|businesswire|globenewswire)")

def _tokens(s):
    return set(w for w in norm(s).split() if len(w) > 2)

SUFFIX_RX = re.compile(r"\b(inc|llc|l\.l\.c|ltd|llp|l\.l\.p|lp|plc|pllc|p\.c|pc|corp|corporation|company|co|group|holdings|international|incorporated|the)\b\.?,?", re.I)
def name_variants(org):
    base = re.sub(r"\s+", " ", SUFFIX_RX.sub(" ", re.sub(r"[,.&]", " ", org))).strip()
    base = re.sub(r"^(city|county|town|village) of ", "", base, flags=re.I)
    words = base.split()
    seen, out = set(), []
    for n in (len(words), 4, 3, 2):
        v = " ".join(words[:n])
        if len(words) >= n >= 1 and v and v.lower() not in seen:
            seen.add(v.lower()); out.append(v)
    return out or [org]

GENERIC = set("inc llc ltd llp lp plc pllc pc corp corporation company co group holdings international incorporated the of and for county city town village district school schools public services service solutions partners associates associates bank credit union health healthcare medical center centre hospital clinic law firm office offices financial insurance management systems technologies technology america american usa us national global".split())
def _foreign(domain):
    """Two-letter country TLD other than the ones US/Canada companies actually use."""
    tld = domain.rsplit(".", 1)[-1]
    if re.search(r"\.(co|com|org|net|ac|gov|edu)\.[a-z]{2}$", domain):
        return True
    return len(tld) == 2 and tld not in {"us", "ca", "co", "io", "ai", "me", "tv", "cc", "ly", "fm", "gg", "to", "sh"}
class _F:  # keeps the FOREIGN_TLD.search(x) call sites
    @staticmethod
    def search(d): return _foreign(d)
FOREIGN_TLD = _F()
def sig(s):
    return set(w for w in norm(s).split() if len(w) > 2 and w not in GENERIC)

FOREIGN_SUFFIX = re.compile(r"\b(ltd|limited|pvt|gmbh|s\.?a\.?|pty|bhd|sdn|plc|ag|nv|bv|oy|ab|as|kk|srl|spa|sas|sarl)\b\.?", re.I)

def domain_matches(domain, cand_name, org):
    """Strict: the candidate's distinctive words must all belong to the org, the
    candidate must not carry a foreign corporate suffix the org lacks, and the
    domain stem must be built from the org's words or initials. 'McMinnville
    Funeral Home' for 'City of McMinnville' fails; 'Winona County Fair' fails;
    'National Life Insurance Company Ltd' (Bangladesh) fails."""
    if not domain or DOMAIN_BLOCK.search(domain) or FOREIGN_TLD.search(domain):
        return False
    so, sc = sig(org), sig(cand_name)
    if not so:
        return False
    if cand_name and FOREIGN_SUFFIX.search(cand_name) and not FOREIGN_SUFFIX.search(org):
        return False
    if sc and not sc <= so:
        return False
    stem = re.sub(r"[^a-z0-9]", "", domain.split(".")[0])
    stem_hits = [w for w in so if len(w) >= 4 and w in stem]
    words = [w for w in re.sub(r"[^a-z0-9 ]", " ", (org or "").lower()).split() if w not in ("the", "of", "and", "a", "an", "d", "b", "dba")]
    initials = "".join(w[0] for w in words)
    stem2 = re.sub(r"^the", "", stem)
    acronym = len(initials) >= 2 and len(stem2) >= 2 and (stem2.startswith(initials) or (len(stem2) >= 3 and initials.startswith(stem2))) and len(stem2) <= len(initials) + 6
    if stem_hits or acronym:
        return True
    return bool(sc) and sc == so and len(so) >= 2   # Clearbit's canonical name is the whole org name

PERSON_RX = re.compile(r"^(Dr\.? |Mr\.? |Ms\.? )?[A-Z][a-z]+ ([A-Z]\.? |[A-Z][a-z]+ )?[A-Z][a-z]+(,? (Jr|Sr|II|III|MD|DDS|CPA|Esq)\.?)?$")

def domain_clearbit(org):
    if re.match(r"^(city|county|town|village|state|borough) of \b", org, re.I) or re.search(r"\b(county|school district|boces|unified|public schools)\b", org, re.I):
        return "", ""   # Clearbit does not know governments; it guesses businesses with the same place name
    if PERSON_RX.match(org) and not sig(org) & {"group", "associates", "partners"}:
        return "", ""   # an individual filer (sole proprietor, trustee); any company match is a coincidence
    variants = name_variants(org)
    words = [w for w in variants[0].split() if w.lower() not in GENERIC]
    if words and len(words[0]) >= 6 and words[0].lower() not in GENERIC:
        variants.append(words[0])   # distinctive first word alone, e.g. Fragomen, Advantest, Covercraft
    for v in variants:
        try:
            raw = get("https://autocomplete.clearbit.com/v1/companies/suggest?query=" + urllib.parse.quote(v[:60]), timeout=15, retries=0)
            cands = [c for c in json.loads(raw)[:5] if domain_matches(c.get("domain", ""), c.get("name", ""), org)]
            cands.sort(key=lambda c: (len(sig(c.get("name", "")) & sig(org)), c["domain"].endswith((".com", ".org", ".net", ".us", ".ca", ".edu", ".bank"))), reverse=True)
            if cands:
                return cands[0]["domain"], "clearbit"
        except Exception:
            pass
        time.sleep(0.3)
    return "", ""

# ----------------------------------------------------------------------------
# notice letters (CA, WA, DE, HI attach the consumer letter as PDF). The letter
# names the vector ("What happened") and almost always carries the org's own
# email/web domain. pypdf is optional; without it letters are skipped.
# ----------------------------------------------------------------------------
VENDOR_RX = re.compile(r"(experian|equifax|transunion|idx\.us|idx\.com|kroll|cyberscout|epiq|identityforce|identityguard|myidcare|idwatchdog|allclear|zix|annualcreditreport|ftc\.gov|consumer\.gov|identitytheft\.gov|\.gov$|lifelock|norton|idtheft|cloudflare|adobe|microsoft|google|apple|amazon|docusign|constantcontact|mailchimp|sendgrid|example\.com|idprotection|credit|monitoring|enroll|claimsdepot|kcc\.com|epiqglobal|idresolution|cyberscout|sontiq|aura\.com|clearme|fraud|privacy@|notice|response|incident|breach|cmpd|idme|id\.me)", re.I)

def pdf_text(url, max_pages=4):
    try:
        import io, pypdf
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=60) as r:
            data = r.read(6_000_000)
        rd = pypdf.PdfReader(io.BytesIO(data))
        return " ".join((p.extract_text() or "") for p in rd.pages[:max_pages])
    except Exception:
        return ""

def letter_facts(text, org):
    """-> (excerpt, domain). excerpt = the 'what happened' paragraph."""
    t = re.sub(r"\s+", " ", (text or "").replace("“", '"').replace("”", '"').replace("’", "'").replace("‘", "'").replace("­", ""))
    if not t:
        return "", ""
    excerpt = ""
    m = re.search(r"(?:WHAT HAPPENED|What Happened|What happened)\??\s*[:.]?\s*(?=[A-Z(\"'])(.{80,700}?)(?=\s*(What Information|WHAT INFORMATION|What We Are Doing|WHAT WE ARE DOING|What You Can Do|WHAT YOU CAN DO|The Information Involved|For More Information|FOR MORE INFORMATION)\b|$)", t, re.S)
    if m:
        excerpt = m.group(1).strip()
    else:  # incident narratives almost always open with a date
        m = re.search(r"((?:On|In|Between|Around|On or about|In early|In late)\s+(?:or about\s+)?(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{0,2},?\s*\d{4}.{80,600})", t)
        excerpt = m.group(1).strip() if m else ""
    if not excerpt:
        m = re.search(r"(?:Dear [^.]{0,80}[.,:])\s*(.{80,600})", t, re.S)
        excerpt = m.group(1).strip() if m else t[:500]
    excerpt = re.sub(r"\s+", " ", excerpt)
    cands = []
    for mm in re.finditer(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", t):
        cands.append((mm.group(1).lower(), 2))
    for mm in re.finditer(r"(?:https?://|www\.)([A-Za-z0-9.-]+\.[A-Za-z]{2,})", t):
        cands.append((re.sub(r"^www\.", "", mm.group(1).lower()), 1))
    best, score = "", 0
    for d, w in cands:
        if VENDOR_RX.search(d) or not domain_matches(d, "", org):
            continue
        if w > score:
            best, score = d, w
    return excerpt[:600], best

def enrich_from_letters(rows, cache_path):
    try:
        cache = json.load(open(cache_path, encoding="utf-8"))
    except Exception:
        cache = {}
    n = 0
    for r in rows:
        u = r.get("letter_url")
        if not u or not u.lower().split("?")[0].endswith(".pdf"):
            continue
        if u not in cache:
            ex, d = letter_facts(pdf_text(u), r["org"])
            cache[u] = {"excerpt": ex, "domain": d}
            n += 1
        ex, d = cache[u]["excerpt"], cache[u]["domain"]
        if ex and len(ex.strip()) > 40:
            r["detail"] = ("Letter: " + ex)[:400]
        if d and not r.get("domain"):
            r["domain"], r["domain_source"] = d, "notice letter"
    try:
        json.dump(cache, open(cache_path, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    except Exception:
        pass
    return n

def clean_domain(d):
    d = (d or "").strip().lower()
    d = re.sub(r"^https?:/{0,2}", "", d); d = re.sub(r"^www\.", "", d); d = d.split("/")[0].split("?")[0]
    return d if re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", d) else ""


def resolve_domains(rows, cache_path):
    try:
        cache = json.load(open(cache_path, encoding="utf-8"))
    except Exception:
        cache = {}
    looked = 0
    for r in rows:
        if r.get("domain"):
            r["domain_source"] = r.get("domain_source") or "source record"
            continue
        key = norm(r["org"])
        if key in cache and (cache[key]["domain"] or cache[key].get("ts", "") >= (TODAY - dt.timedelta(days=30)).isoformat()):
            r["domain"], r["domain_source"] = cache[key]["domain"], cache[key]["via"]
            continue
        d, via = domain_clearbit(r["org"])
        cache[key] = {"domain": d, "via": via or "not found", "org": r["org"], "ts": TODAY.isoformat()}
        r["domain"], r["domain_source"] = d, via or "not found"
        looked += 1
    try:
        json.dump(cache, open(cache_path, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    except Exception:
        pass
    return looked

# tier 1 = legally mandated filing, 2 = leak-site claim / breach catalog, 3 = law-firm investigation, 4 = news headline
TIER = {"state_ca": 1, "state_wa": 1, "state_vt": 1, "state_or": 1, "state_de": 1, "state_hi": 1,
        "rwl": 2, "hibp": 2, "rss_sb": 3, "rss_lc": 3, "rss_dbn": 4, "gnews_us": 4, "gnews_ca": 4}

def norm(s):
    s = re.sub(r"[^a-z0-9 ]", " ", (s or "").lower())
    s = re.sub(r"\b(inc|llc|ltd|corp|corporation|company|co|plc|pllc|lp|the)\b", " ", s)
    return re.sub(r"\s+", " ", s).strip()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=14)
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "breach_signals.csv"))
    ap.add_argument("--only", default="", help="comma list of source keys")
    ap.add_argument("--json", default="", help="also write a JSON feed (for the site / POE)")
    ap.add_argument("--no-domains", action="store_true", help="skip web domain lookup")
    ap.add_argument("--keep-news", action="store_true", help="keep unmatched news headlines as rows (default: drop)")
    a = ap.parse_args()
    keys = [k.strip() for k in a.only.split(",") if k.strip()] or list(SOURCES)

    rows, status = [], []
    for k in keys:
        t0 = time.time()
        try:
            got = SOURCES[k](a.days)
            rows += got
            status.append((k, "ok", len(got), round(time.time() - t0, 1)))
        except Exception as e:
            status.append((k, f"FAIL {type(e).__name__}: {str(e)[:80]}", 0, round(time.time() - t0, 1)))

    # de-dupe: same org (normalized) -> keep one row, merge source names.
    # News rows (tier 4) never create an org record on their own; they attach to
    # an existing org whose name appears in the headline, else go to the bottom.
    merged = {}
    dropped = len(rows)
    rows = [r for r in rows if north_america(r)]
    dropped -= len(rows)
    for r in rows:
        r["org"] = clean_org(r["org"])
        r["breach_date"] = iso(r["breach_date"])
        r["affected"] = to_int(r["affected"])
    rows.sort(key=lambda r: TIER.get(r["source"], 9))
    news = []
    for r in rows:
        key = norm(r["org"])
        if not key:
            continue
        if TIER.get(r["source"], 9) >= 4:
            hit = next((k for k in merged if len(k) >= 6 and k in norm(r["detail"])), None)
            if hit:
                m = merged[hit]
                if r["source"] not in m["source"]:
                    m["source"] += "+" + r["source"]
                m["detail"] = (m["detail"] + " || " + r["detail"])[:400]
                m["reported_to"] += " | " + r["reported_to"]
                m["product_fit"] = product_fit(m["detail"] + " " + m["sector"])
            else:
                news.append(r)
            continue
        if key in merged:
            m = merged[key]
            if r["source"] not in m["source"]:
                m["source"] += "+" + r["source"]
            if r["reported"] > m["reported"]:
                m["reported"] = r["reported"]
            for f in ("affected", "breach_date", "domain", "sector", "state", "letter_url"):
                if not m[f] and r[f]:
                    m[f] = r[f]
            m["reported_to"] += " | " + r["reported_to"]
            m["detail"] = (m["detail"] + " || " + r["detail"])[:400]
            m["product_fit"] = product_fit(m["detail"] + " " + r["detail"] + " " + m["sector"])
        else:
            merged[key] = dict(r)
    for r in merged.values():
        r["tier"] = min(TIER.get(s, 9) for s in r["source"].split("+"))
    out = sorted(merged.values(), key=lambda r: (-r["tier"], r["source"].count("+"), r["reported"]), reverse=True)
    # news headlines are not org records: dropped unless --keep-news
    if a.keep_news:
        seen = set()
        for r in news:
            k = norm(r["org"])
            if k in seen:
                continue
            seen.add(k); r["tier"] = 4; out.append(r)
    here = os.path.dirname(os.path.abspath(__file__))
    for r in out:
        r["domain"] = clean_domain(r.get("domain", ""))
        r.setdefault("domain_source", "")
    letters = enrich_from_letters(out, os.path.join(here, "letters.json"))
    looked = 0
    if not a.no_domains:
        looked = resolve_domains(out, os.path.join(here, "domains.json"))
    for r in out:
        r["incident_type"] = incident_type(r["detail"] + " " + r["sector"])
        r["product_fit"] = product_fit(r["detail"] + " " + r["sector"] + " " + r["org"])

    cols = ["tier", "reported", "org", "domain", "domain_source", "country", "state", "sector", "affected", "breach_date",
            "incident_type", "product_fit", "reported_to", "source", "detail", "url", "letter_url"]
    with open(a.out, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in out:
            w.writerow({c: r.get(c, "") for c in cols})
    if a.json:
        feed = {
            "generated_utc": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "window_days": a.days,
            "tiers": {"1": "mandatory government filing", "2": "leak-site claim or verified credential dump",
                      "3": "plaintiff-firm investigation (follows a consumer notice)", "4": "news headline, not an org record"},
            "sources": [{"key": k, "status": s, "rows": n, "seconds": sec} for k, s, n, sec in status],
            "manual_sources": [{"name": n_, "url": u} for n_, u in MANUAL_SOURCES],
            "count": len(out),
            "signals": [{c: r.get(c, "") for c in cols} for r in out],
        }
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(feed, f, ensure_ascii=False, indent=1)

    print(f"\nwindow: last {a.days} days   unique orgs: {len(out)}   raw rows: {len(rows)}   dropped non-US/CA: {dropped}   "
          f"news headlines unmatched: {len(news)}   letters read: {letters}   domains looked up: {looked}   with domain: {sum(1 for r in out if r['domain'])}   -> {a.out}")
    print(f"{'source':10} {'status':44} {'rows':>5} {'sec':>5}")
    for k, s, n, sec in status:
        print(f"{k:10} {s[:44]:44} {n:5d} {sec:5}")
    print("\nMANUAL sources to check this week (not scriptable):")
    for name, url in MANUAL_SOURCES:
        print(f"  - {name}\n      {url}")

if __name__ == "__main__":
    main()
