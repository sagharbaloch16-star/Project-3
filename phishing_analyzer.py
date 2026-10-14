#!/usr/bin/env python3
"""
Phishing Awareness Analyzer  -  DecodeLabs Cyber Security, Project 3
=====================================================================

Goal
    Analyze sample e-mails / messages to identify phishing attempts.

What it does (maps to the three Key Requirements of the project)
    1. Identifies suspicious links and keywords
    2. Lists every red flag it finds (sender, headers, links, content, attachments)
    3. Explains WHY the message is unsafe and ends with a definitive triage action:
           SAFE       -> Close
           SUSPICIOUS -> Warn User
           MALICIOUS  -> Block Domain & Escalate

Usage
    python phishing_analyzer.py                  # run all built-in sample e-mails
    python phishing_analyzer.py --samples        # same as above
    python phishing_analyzer.py --interactive    # type / paste your own message
    python phishing_analyzer.py --eml mail.eml   # analyze a real .eml file (headers included)
    python phishing_analyzer.py --json-in sample_emails.json
    python phishing_analyzer.py --samples --json # machine-readable output
    python phishing_analyzer.py --samples --company-domain company.example

Safety notes
    * Nothing is sent over the network. The tool only READS text and never opens links.
    * All sample e-mails use reserved ".example" domains and fake phone numbers, so
      no real website, brand or person is contacted or targeted.
    * URLs in the report are "defanged" (hxxp / [.]) so they cannot be clicked by accident.
"""

import argparse
import html as html_lib
import json
import re
import sys
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from urllib.parse import urlparse

# --------------------------------------------------------------------------
# Knowledge base
# --------------------------------------------------------------------------
SEV_POINTS = {"high": 4, "medium": 2, "low": 1}

FREE_MAIL = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com", "aol.com",
    "proton.me", "protonmail.com", "icloud.com", "mail.com", "gmx.com", "yandex.com",
    "zoho.com",
}

# brand keyword -> domains that really belong to that brand
BRANDS = {
    "microsoft": ["microsoft.com", "office.com", "microsoftonline.com", "office365.com"],
    "paypal": ["paypal.com"],
    "amazon": ["amazon.com"],
    "google": ["google.com", "youtube.com"],
    "linkedin": ["linkedin.com"],
    "apple": ["apple.com", "icloud.com"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "meta.com", "fb.com"],
    "chatgpt": ["openai.com", "chatgpt.com"],
    "openai": ["openai.com", "chatgpt.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
}

ROLE_WORDS = [
    "ceo", "cfo", "coo", "cto", "director", "president", "chairman",
    "managing director", "hr", "human resources", "it support", "it security",
    "helpdesk", "help desk", "payroll", "finance", "accounts", "security team",
    "administrator",
]

COMBO_WORDS = [
    "secure", "login", "signin", "verify", "update", "account", "support", "billing",
    "portal", "auth", "alert", "helpdesk", "service", "confirm", "recovery", "unlock",
    "wallet",
]

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "buff.ly", "tiny.cc", "rb.gy",
}

SUSPICIOUS_TLDS = {
    ".zip", ".mov", ".xyz", ".top", ".click", ".tk", ".icu", ".gq", ".ml", ".cf",
    ".work", ".support", ".rest", ".country", ".kim", ".men", ".loan",
}

TLD_WORDS = {"com", "net", "org", "tech", "io", "co", "gov", "edu", "info", "biz"}
TWO_LEVEL = {"co.uk", "org.uk", "gov.uk", "ac.uk", "com.pk", "net.pk", "org.pk",
             "co.in", "com.au", "co.jp", "com.br", "co.za", "com.cn"}

DANGEROUS_EXT = {".iso", ".img", ".js", ".scr", ".exe", ".vbs", ".hta", ".lnk", ".bat",
                 ".cmd", ".msi", ".jar", ".ps1"}
RISKY_EXT = {".html", ".htm", ".zip", ".rar", ".7z", ".docm", ".xlsm", ".pptm", ".svg", ".one"}

# Psychological / keyword lists (matched at the start of a word, case-insensitive)
URGENCY = ["urgent", "immediately", "asap", "expir", "suspend", "final notice", "last warning",
           "act now", "action required", "overdue", "right away",
           "before the close of business", "deadline", "by end of day", "account locked",
           "locked out", "lockout", "today only", "time-sensitive"]
URGENCY_RE = re.compile(r"within (?:the next )?\d+\s?(?:minutes|mins|hours|hrs)", re.I)
SECRECY = ["strictly confidential", "do not discuss", "don't discuss", "do not tell",
           "don't tell", "bypass", "keep this between us", "keep this confidential",
           "do not share this", "don't share this"]
SENSITIVE = ["password", "passcode", "otp", "verification code", "one-time code", "mfa code",
             "security code", "verify your identity", "verify your account",
             "confirm your identity", "confirm your account", "billing information",
             "billing details", "payment details", "account number", "card number", "cvv",
             "social security", "login credentials", "sign in to"]
FEAR_GREED = ["legal action", "lawsuit", "arrest", "penalty", "terminated", "terminate your",
              "you have won", "winner", "prize", "refund", "reward", "unclaimed",
              "inheritance", "unauthorized", "unauthorised", "unusual sign-in",
              "unusual activity", "suspicious activity"]
PAYMENT = ["wire transfer", "wire funds", "wire the", "transfer funds", "gift card",
           "new bank", "bank details", "payment instruction", "update billing",
           "update your billing", "change of bank"]
GENERIC = ["dear customer", "dear user", "dear valued", "dear account holder", "dear client",
           "dear member", "dear sir", "dear madam"]
QR_TERMS = ["scan the qr", "scan this qr", "scan the code", "scan to ", "qr code"]

URL_RE = re.compile(r'''(?:https?|hxxps?)://[^\s<>"')\]]+''', re.I)
WWW_RE = re.compile(r'''(?<![/\w.])www\.[^\s<>"')\]]+''', re.I)
MD_LINK_RE = re.compile(r'''\[([^\]]+)\]\(((?:https?|hxxps?)://[^)\s]+)\)''', re.I)
PHONE_RE = re.compile(r"(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?){2}\d{4}|\b1-8\d\d-[\w-]+")

CAT_TEXT = {
    "sender": "the sender is not who they claim to be",
    "headers": "the technical e-mail headers do not add up",
    "link": "the links hide or disguise where they really lead",
    "content": "the wording tries to rush, scare or tempt the reader into skipping verification",
    "attachment": "the attachment type can run code on the device",
}

ACTIONS = {
    "SAFE": ("Close", [
        "Close the ticket - no action needed.",
        "If something still feels off, verify out-of-band (call a known directory number).",
    ]),
    "SUSPICIOUS": ("Warn User", [
        "Warn the user: do NOT click links, scan codes or open attachments.",
        "Verify the request through a second channel (known phone number / in-person).",
        "Report the message through the internal reporting button - do not just delete it.",
    ]),
    "MALICIOUS": ("Block Domain & Escalate", [
        "Block the sender domain and every domain / URL listed under Indicators.",
        "Escalate to the security team / incident response.",
        "Search other mailboxes for the same message and purge it everywhere.",
        "If anyone clicked or typed credentials: reset password, revoke sessions, review MFA devices.",
    ]),
}


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def flag(category, severity, title, detail, evidence=None):
    return {"category": category, "severity": severity, "title": title,
            "detail": detail, "evidence": evidence or []}


def defang(text):
    return text.replace("http", "hxxp", 1).replace(".", "[.]")


def addr_domain(addr):
    m = re.search(r"@([A-Za-z0-9.\-]+)", addr or "")
    return m.group(1).lower().strip(".") if m else ""


def registered_domain(host):
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if ".".join(parts[-2:]) in TWO_LEVEL and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def is_legit(host, brand):
    return any(host == d or host.endswith("." + d) for d in BRANDS[brand])


def edit_distance(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def variants(label):
    """Undo common look-alike tricks: 0->o, 1->l/i, 3->e, 5->s, 4->a, rn->m, vv->w."""
    out = set()
    for one in ("l", "i"):
        t = label.translate(str.maketrans({"0": "o", "1": one, "3": "e", "5": "s", "$": "s", "4": "a"}))
        out.add(t.replace("rn", "m").replace("vv", "w"))
    return out


def find_terms(text, terms):
    """Return the words actually found in the text (matched at a word start)."""
    out = []
    for t in terms:
        m = re.search(r"(?<!\w)" + re.escape(t) + r"\w*", text, re.I)
        if m:
            out.append(m.group(0).lower())
    return out


# --------------------------------------------------------------------------
# Domain / URL analysis
# --------------------------------------------------------------------------
def analyze_host(host, where, category):
    host = (host or "").lower().strip(".")
    out = []
    if not host:
        return out

    def add(sev, title, detail):
        out.append(flag(category, sev, title, detail, [host]))

    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        add("high", "IP address instead of a domain name",
            f"The {where} uses a raw IP address. Real companies use their own domain name, "
            "so an IP hides who owns the server.")
        return out

    if host.startswith("xn--") or ".xn--" in host or any(ord(c) > 127 for c in host):
        add("high", "Punycode / look-alike (homoglyph) characters",
            f"The {where} contains characters from another alphabet that look identical to "
            "Latin letters (e.g. a Cyrillic 'a'), a classic homoglyph attack.")

    reg = registered_domain(host)
    tld = "." + host.rsplit(".", 1)[-1]

    if where == "link" and reg in SHORTENERS:
        add("medium", "URL shortener hides the real destination",
            "Shorteners hide where the link really goes, so the user cannot judge it before clicking.")

    if tld in SUSPICIOUS_TLDS:
        add("medium", f"Suspicious top-level domain ({tld})",
            f"The {tld} TLD is cheap and heavily abused for throw-away phishing sites.")

    sub = host[: -(len(reg) + 1)] if host != reg else ""
    trap = False
    if sub:
        labels = sub.split(".")
        brand_in_sub = [b for b in BRANDS if len(b) >= 5 and b in sub and not is_legit(host, b)]
        tld_in_sub = any(l in TLD_WORDS for l in labels[1:])
        if brand_in_sub or tld_in_sub:
            trap = True
            add("high", "Subdomain trap (trusted name buried in front of the real domain)",
                f"The real owner of this address is '{reg}'. Everything to its left is just a "
                "prefix the attacker chose to look trustworthy. Read domains right-to-left.")
        elif sub.count(".") >= 3:
            add("low", "Excessive number of subdomains",
                "Long chains of subdomains are often used to push the real domain out of view.")

    label = reg.split(".")[0]
    vs = variants(label)
    for b in BRANDS:
        if len(b) < 5 or is_legit(host, b):
            continue
        if label != b and (b in vs or edit_distance(label, b) == 1):
            add("high", f"Typosquatting of '{b}'",
                f"'{label}' is one character away from the real brand '{b}' (or uses digits "
                "that look like letters).")
            break
        if b in label and label != b:
            if any(w in label for w in COMBO_WORDS):
                add("high", f"Combosquatting of '{b}'",
                    f"The domain glues security words onto the brand name '{b}'. The real brand "
                    "never uses this domain.")
            else:
                add("medium", f"Brand name '{b}' inside an unrelated domain",
                    f"The domain contains '{b}' but is not owned by that brand.")
            break

    if not trap and not label.startswith("xn--") and label.count("-") >= 3:
        add("low", "Many hyphens in the domain",
            "Domains such as 'secure-login-update-now' are typical of phishing infrastructure.")
    return out


def analyze_url(url):
    try:
        p = urlparse(url)
        host = p.hostname or ""
    except ValueError:
        return [flag("link", "medium", "Malformed URL", "The link is badly formed.", [defang(url)])]
    flags = []
    if "@" in p.netloc:
        flags.append(flag("link", "high", "'@' trick in the URL",
                          "Everything before '@' is ignored by the browser; the real site is "
                          "whatever comes after it.", [defang(url)]))
    flags += analyze_host(host, "link", "link")
    if p.scheme == "http":
        flags.append(flag("link", "low", "Unencrypted http:// link",
                          "Legitimate sign-in pages use https. Plain http is a weak signal on its own.", []))
    for f in flags:
        f["evidence"] = [defang(url)]
    return flags


def extract_links(body):
    links, seen = [], set()

    def norm(u):
        return re.sub(r"[.,;:!?]+$", "", re.sub(r"^hxxp", "http", u, flags=re.I))

    for m in MD_LINK_RE.finditer(body):
        url = norm(m.group(2))
        links.append({"label": m.group(1), "url": url})
        seen.add(url)
    for m in URL_RE.finditer(body):
        url = norm(m.group(0))
        if url not in seen:
            seen.add(url)
            links.append({"label": "", "url": url})
    labels = {l["label"] for l in links}
    for m in WWW_RE.finditer(body):
        raw = re.sub(r"[.,;:!?]+$", "", m.group(0))
        url = "http://" + raw
        if raw not in labels and url not in seen:
            seen.add(url)
            links.append({"label": "", "url": url})
    return links


def label_mismatch(link):
    label = link["label"].strip()
    if not label or not re.fullmatch(r"(?:https?://)?(?:www\.)?[\w-]+(?:\.[\w-]+)+(?:/\S*)?", label, re.I):
        return None
    try:
        lh = (urlparse(label if re.match(r"https?://", label, re.I) else "http://" + label).hostname or "")
        ah = urlparse(link["url"]).hostname or ""
    except ValueError:
        return None
    lh = re.sub(r"^www\.", "", lh)
    if registered_domain(lh) != registered_domain(ah):
        return flag("link", "high", "Link text shows one address but points to another",
                    f"The visible text says '{lh}' but the link really goes to '{ah}'. "
                    "Always hover over (or long-press) a link before trusting it.",
                    [defang(link["url"])])
    return None


# --------------------------------------------------------------------------
# Sender / header analysis
# --------------------------------------------------------------------------
def analyze_sender(m, company_domain):
    flags = []
    name = m.get("from_name") or ""
    addr = m.get("from_addr") or ""
    dom = addr_domain(addr)
    lname = name.lower()
    cd = (company_domain or m.get("company_domain") or "").lower().strip()

    for b in BRANDS:
        if b in lname and not is_legit(dom, b):
            flags.append(flag("sender", "high", "Sender-domain mismatch (display-name spoofing)",
                              f"The display name says '{name}' but the address really belongs to '{dom}'. "
                              "Anyone can type any display name - the domain is what counts.",
                              [f"{name} <{addr}>"]))
            break

    role = next((r for r in ROLE_WORDS if re.search(r"(?<!\w)" + re.escape(r) + r"(?!\w)", lname)), None)
    if role:
        if dom in FREE_MAIL:
            flags.append(flag("sender", "high", "Executive / internal role sent from a free e-mail account",
                              f"A message claiming to be '{name}' arrives from a free provider ({dom}). "
                              "Real executives and departments write from the company domain.",
                              [f"{name} <{addr}>"]))
        elif cd and not (dom == cd or dom.endswith("." + cd)):
            flags.append(flag("sender", "high", "Claims to be internal but sends from an external domain",
                              f"'{name}' sounds internal, but the domain '{dom}' is not the company "
                              f"domain '{cd}'.", [f"{name} <{addr}>"]))

    flags += analyze_host(dom, "sender domain", "sender")

    rdom = addr_domain(m.get("reply_to") or "")
    if rdom and dom and rdom != dom:
        flags.append(flag("headers", "high", "Reply-To differs from From",
                          f"Replies would go to '{rdom}' instead of '{dom}'. Attackers use this to "
                          "keep the victim talking while looking like a trusted sender.",
                          [f"From: {dom}  |  Reply-To: {rdom}"]))

    rp = addr_domain(m.get("return_path") or "")
    if rp and dom and registered_domain(rp) != registered_domain(dom):
        flags.append(flag("headers", "medium", "Return-Path differs from From",
                          f"The bounce address ('{rp}') belongs to a different domain than the visible "
                          f"sender ('{dom}'). Mailing services do this legitimately, but it is also "
                          "typical of spoofed mail.",
                          [f"From: {dom}  |  Return-Path: {rp}"]))

    auth = m.get("auth_results") or ""
    bad = re.findall(r"\b(spf|dkim|dmarc)=(fail|softfail|permerror|temperror)\b", auth, re.I)
    if bad:
        flags.append(flag("headers", "high", "E-mail authentication failed (SPF / DKIM / DMARC)",
                          "The receiving server could not prove the message really came from the "
                          "claimed domain.", [", ".join(f"{a.lower()}={b.lower()}" for a, b in bad)]))

    subj = m.get("subject") or ""
    if re.match(r"\s*(fw|fwd)\s*:", subj, re.I) and (find_terms(subj, URGENCY) or URGENCY_RE.search(subj)):
        flags.append(flag("headers", "medium", "Fake forwarded chain",
                          "Attackers prefix 'FW:' to make an alarming message look like part of a "
                          "conversation the user was already in.", [subj]))
    return flags


# --------------------------------------------------------------------------
# Content analysis
# --------------------------------------------------------------------------
def analyze_content(m, links):
    subject = m.get("subject") or ""
    body = m.get("body") or ""
    text = subject + "\n" + body
    text = re.sub(r"\b(non[- ]?urgent|not urgent|no immediate action[^.\n]*)", "", text, flags=re.I)
    flags = []

    urg = find_terms(text, URGENCY)
    urg += [x.group(0).lower() for x in URGENCY_RE.finditer(text)]
    if urg:
        flags.append(flag("content", "medium", "Urgency / time pressure",
                          "Artificial deadlines trigger a fight-or-flight reaction and cut rational checking.",
                          sorted(set(urg))))
    sec = find_terms(text, SECRECY)
    if sec:
        flags.append(flag("content", "high", "Secrecy / request to bypass procedure",
                          "Real organisations never ask staff to hide a request or skip approval steps.",
                          sorted(set(sec))))
    sens = find_terms(text, SENSITIVE)
    if sens:
        flags.append(flag("content", "medium", "Request for sensitive information or credentials",
                          "Passwords, MFA codes, account or card numbers are never requested over e-mail.",
                          sorted(set(sens))))
    pay = find_terms(text, PAYMENT)
    if pay:
        flags.append(flag("content", "medium", "Payment / money-transfer request",
                          "Unexpected payment or bank-detail changes are the core of Business E-mail Compromise (BEC).",
                          sorted(set(pay))))
    fg = find_terms(text, FEAR_GREED)
    if fg:
        flags.append(flag("content", "medium", "Fear or greed trigger",
                          "Threats of loss or promises of rewards push people to act before thinking.",
                          sorted(set(fg))))
    gen = find_terms(text, GENERIC)
    if gen:
        flags.append(flag("content", "low", "Generic greeting",
                          "Companies that hold your account usually address you by name.", sorted(set(gen))))
    qr = find_terms(text, QR_TERMS)
    if qr:
        flags.append(flag("content", "medium", "QR-code prompt (quishing)",
                          "QR codes move the victim to a phone where URL filters and domain checks are weaker.",
                          sorted(set(qr))))

    phones = [p.strip() for p in PHONE_RE.findall(text)]
    if phones and re.search(r"\bcall\b", text, re.I):
        if not links:
            flags.append(flag("content", "high", "Callback scam (TOAD) - phone number but no link",
                              "No malicious link to scan for: the attack happens on the phone, where the "
                              "attacker impersonates 'support'.", phones[:3]))
        else:
            flags.append(flag("content", "medium", "Message pushes you to call a phone number",
                              "Never call numbers given in a suspicious message; use the official website.",
                              phones[:3]))
    return flags, phones


def analyze_attachments(m):
    flags = []
    for name in m.get("attachments") or []:
        n = name.lower()
        ext = "." + n.rsplit(".", 1)[-1] if "." in n else ""
        if re.search(r"\.\w{2,4}\.(exe|scr|js|vbs|bat|lnk|iso)$", n):
            flags.append(flag("attachment", "high", "Double file extension",
                              "A name such as 'invoice.pdf.exe' disguises a program as a document.", [name]))
        elif ext in DANGEROUS_EXT:
            flags.append(flag("attachment", "high", f"Dangerous attachment type ({ext})",
                              "This file type can execute code or mount a disk image and is rarely sent legitimately.",
                              [name]))
        elif ext in RISKY_EXT:
            flags.append(flag("attachment", "medium", f"Risky attachment type ({ext})",
                              "Archives, macro files and HTML attachments are used for malware and HTML smuggling.",
                              [name]))
    return flags


# --------------------------------------------------------------------------
# Main analysis + report
# --------------------------------------------------------------------------
def analyze(m, company_domain=None):
    body = m.get("body") or ""
    links = extract_links(body)
    flags = analyze_sender(m, company_domain)
    for link in links:
        lm = label_mismatch(link)
        if lm:
            flags.append(lm)
        flags += analyze_url(link["url"])
    content_flags, phones = analyze_content(m, links)
    flags += content_flags
    flags += analyze_attachments(m)

    uniq, seen = [], set()
    for f in flags:
        key = (f["category"], f["title"], tuple(f["evidence"]))
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    order = {"high": 0, "medium": 1, "low": 2}
    uniq.sort(key=lambda f: order[f["severity"]])

    score = sum(SEV_POINTS[f["severity"]] for f in uniq)
    highs = sum(1 for f in uniq if f["severity"] == "high")
    if score >= 6 and highs >= 1:
        verdict = "MALICIOUS"
    elif score >= 3:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"
    action, steps = ACTIONS[verdict]

    cats = []
    for f in uniq:
        if f["severity"] != "low" and f["category"] not in cats:
            cats.append(f["category"])
    if verdict == "SAFE":
        why = ("No meaningful red flags were found: the sender, headers, links and wording are consistent. "
               "Stay alert anyway - verify any unexpected request out-of-band.")
    else:
        reasons = "; ".join(CAT_TEXT[c] for c in cats) or "several weak warning signs add up"
        why = (f"This message is classified {verdict} (score {score}) because {reasons}. "
               "Taken together these are the hallmarks of a social-engineering attack: a disguise "
               "(who is writing), a lure (what they want) and pressure (why you must hurry).")

    domains = []
    d = addr_domain(m.get("from_addr") or "")
    if d:
        domains.append(d)
    for l in links:
        h = (urlparse(l["url"]).hostname or "")
        if h and h not in domains:
            domains.append(h)

    return {
        "verdict": verdict, "score": score, "action": action, "steps": steps, "why": why,
        "flags": uniq,
        "indicators": {"urls": [defang(l["url"]) for l in links],
                       "domains": [defang(x) for x in domains],
                       "attachments": m.get("attachments") or [], "phones": phones},
    }


def format_report(m, r, title=None):
    bar = "=" * 72
    L = [bar]
    if title:
        L.append(f"SAMPLE: {title}")
    L.append(f"From    : {m.get('from_name', '')} <{m.get('from_addr', '')}>")
    if m.get("reply_to"):
        L.append(f"Reply-To: {m['reply_to']}")
    L.append(f"Subject : {m.get('subject', '')}")
    L.append(bar)
    L.append(f"VERDICT : {r['verdict']}   (risk score {r['score']})")
    L.append(f"ACTION  : {r['action']}")
    L.append("")
    L.append(f"RED FLAGS FOUND ({len(r['flags'])})")
    if not r["flags"]:
        L.append("  (none)")
    for i, f in enumerate(r["flags"], 1):
        L.append(f"  {i:>2}. [{f['severity'].upper():<6}] ({f['category']}) {f['title']}")
        L.append(f"        why: {f['detail']}")
        if f["evidence"]:
            L.append(f"        evidence: {' | '.join(f['evidence'])}")
    L.append("")
    L.append("WHY THIS MESSAGE IS " + ("UNSAFE" if r["verdict"] != "SAFE" else "CONSIDERED SAFE"))
    L.append("  " + r["why"])
    ind = r["indicators"]
    L.append("")
    L.append("INDICATORS (defanged)")
    L.append("  URLs       : " + (", ".join(ind["urls"]) or "-"))
    L.append("  Domains    : " + (", ".join(ind["domains"]) or "-"))
    L.append("  Attachments: " + (", ".join(ind["attachments"]) or "-"))
    L.append("  Phones     : " + (", ".join(ind["phones"]) or "-"))
    L.append("")
    L.append(f"RECOMMENDED ACTIONS -> {r['action']}")
    for s in r["steps"]:
        L.append(f"  - {s}")
    return "\n".join(L)


# --------------------------------------------------------------------------
# Sample e-mails (all fake; reserved .example domains, fake phone numbers)
# --------------------------------------------------------------------------
SAMPLES = [
    {
        "id": 1, "title": "Fake Microsoft security alert (credential harvesting)", "expected": "MALICIOUS",
        "from_name": "Microsoft Support", "from_addr": "support@logins-updates.example",
        "reply_to": "recover@account-help.example", "return_path": "",
        "auth_results": "spf=fail; dkim=none; dmarc=fail",
        "subject": "FW: Urgent: Your Account Security Alert",
        "body": ("Dear Customer,\n\nWe detected an unusual sign-in to your account from an unknown location. "
                 "Your account will be suspended within 24 hours unless you verify your identity immediately.\n\n"
                 "Sign in now: http://microsoft.com.account-verify.logins-updates.example/signin\n\n"
                 "Please confirm your password and the verification code we send you.\n\n"
                 "Microsoft Account Team"),
        "attachments": ["Security_Update_2026.iso"], "company_domain": "company.example",
    },
    {
        "id": 2, "title": "CEO 'lost wallet' wire-transfer request (BEC)", "expected": "MALICIOUS",
        "from_name": "Michael Reed (CEO)", "from_addr": "m.reed.ceo@gmail.com",
        "reply_to": "m.reed.office@proton.me", "return_path": "", "auth_results": "",
        "subject": "Quick favour - need this today",
        "body": ("Hi,\n\nI lost my wallet at the airport and I'm stuck at the gate. I need you to wire transfer "
                 "funds for my flight immediately, before the close of business. This is strictly confidential - "
                 "do not discuss with anyone and bypass the usual approval steps, I'll explain later.\n\n"
                 "Reply with the account number you will use and I'll send the beneficiary details.\n\n"
                 "Sent from my iPhone\nMichael"),
        "attachments": [], "company_domain": "company.example",
    },
    {
        "id": 3, "title": "Internal IT 'password expires' with subdomain trap", "expected": "MALICIOUS",
        "from_name": "IT Security", "from_addr": "it-security@decodelabs-helpdesk.example",
        "reply_to": "", "return_path": "", "auth_results": "",
        "subject": "Mandatory: Password expires in 24 hrs",
        "body": ("Hello,\n\nYour network password expires in 24 hours. To keep access to your email and files, "
                 "you must update your password today.\n\n"
                 "Update password: [www.decodelabs.tech](http://www.decodelabs.tech.login-update.example/reset)\n\n"
                 "Failure to act will result in your account being locked.\n\nIT Security Team"),
        "attachments": [], "company_domain": "decodelabs.example",
    },
    {
        "id": 4, "title": "Fake Microsoft invoice - callback scam (TOAD), no links", "expected": "MALICIOUS",
        "from_name": "Microsoft Billing", "from_addr": "billing@ms-subscriptions.example",
        "reply_to": "", "return_path": "", "auth_results": "",
        "subject": "Invoice #MS-48213: Subscription renewed - $190.00",
        "body": ("Your Microsoft 365 subscription has been renewed.\n\nAmount charged: $190.00\n\n"
                 "If you did not authorize this charge, call our billing support immediately at "
                 "1-800-555-0142 to cancel and receive a refund. PAYMENT OVERDUE if not disputed within 24 hours."),
        "attachments": ["Invoice_48213.pdf"], "company_domain": "company.example",
    },
    {
        "id": 5, "title": "Genuine internal project update (control sample)", "expected": "SAFE",
        "from_name": "Sarah Lee", "from_addr": "sarah.lee@company.example",
        "reply_to": "", "return_path": "", "auth_results": "spf=pass; dkim=pass; dmarc=pass",
        "subject": "Q3 Project Status Update - Non-Urgent",
        "body": ("Hi Team,\n\nPlease review the attached project status for Q3 at your earliest convenience.\n\n"
                 "No immediate action is required.\n\nThanks,\nSarah"),
        "attachments": ["Q3_Status.pdf"], "company_domain": "company.example",
    },
    {
        "id": 6, "title": "HR benefits questionnaire with shortened link (borderline)", "expected": "SUSPICIOUS",
        "from_name": "Human Resources", "from_addr": "hr@company.example",
        "reply_to": "", "return_path": "", "auth_results": "",
        "subject": "Action Required: 2026 Healthcare Benefits Questionnaire",
        "body": ("Hi all,\n\nPlease complete the 2026 healthcare benefits questionnaire by 5 PM Friday. "
                 "The deadline cannot be extended.\n\nComplete it here: https://bit.ly/2026-benefits\n\n"
                 "Thanks,\nHR Team"),
        "attachments": [], "company_domain": "company.example",
    },
    {
        "id": 7, "title": "Fake Google account recovery - QR code (quishing)", "expected": "MALICIOUS",
        "from_name": "Google Security", "from_addr": "no-reply@accounts-google-recovery.example",
        "reply_to": "", "return_path": "", "auth_results": "",
        "subject": "Action required: Recover your Google Account",
        "body": ("Hello,\n\nWe noticed unusual activity on your Google Account. To prevent account lockout, "
                 "scan the QR code attached to this message within 30 minutes and sign in to confirm it's you.\n\n"
                 "[QR CODE IMAGE]\n\nGoogle Account Recovery Team"),
        "attachments": [], "company_domain": "company.example",
    },
]


# --------------------------------------------------------------------------
# Input loaders / CLI
# --------------------------------------------------------------------------
def html_to_text(h):
    h = re.sub(r"<a\s[^>]*href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>",
               lambda mo: f"[{re.sub(r'<[^>]+>', '', mo.group(2))}]({mo.group(1)})", h, flags=re.I | re.S)
    h = re.sub(r"<(script|style).*?</\1>", " ", h, flags=re.I | re.S)
    return html_lib.unescape(re.sub(r"<[^>]+>", " ", h))


def load_eml(path):
    with open(path, "rb") as fh:
        msg = BytesParser(policy=policy.default).parse(fh)
    name, addr = parseaddr(str(msg.get("From", "")))
    part = msg.get_body(preferencelist=("plain", "html"))
    body = ""
    if part is not None:
        body = part.get_content()
        if part.get_content_type() == "text/html":
            body = html_to_text(body)
    atts = [p.get_filename() for p in msg.iter_attachments() if p.get_filename()]
    return {
        "from_name": name, "from_addr": addr,
        "reply_to": str(msg.get("Reply-To", "")), "return_path": str(msg.get("Return-Path", "")),
        "auth_results": " ".join(str(x) for x in (msg.get_all("Authentication-Results") or [])),
        "subject": str(msg.get("Subject", "")), "body": body, "attachments": atts,
    }


def interactive():
    print("Enter the message details (leave a field empty to skip it).")
    m = {
        "from_name": input("From (display name): "),
        "from_addr": input("From (address)     : "),
        "reply_to": input("Reply-To           : "),
        "subject": input("Subject            : "),
    }
    print("Body - paste text, then type END on its own line:")
    lines = []
    while True:
        line = input()
        if line.strip() == "END":
            break
        lines.append(line)
    m["body"] = "\n".join(lines)
    att = input("Attachments (comma separated): ")
    m["attachments"] = [a.strip() for a in att.split(",") if a.strip()]
    return m


def main():
    ap = argparse.ArgumentParser(description="DecodeLabs Project 3 - Phishing Awareness Analyzer")
    ap.add_argument("--samples", action="store_true", help="analyze the built-in sample e-mails")
    ap.add_argument("--interactive", "-i", action="store_true", help="type / paste your own message")
    ap.add_argument("--eml", help="analyze a .eml file")
    ap.add_argument("--json-in", help="JSON file containing one message object or a list of them")
    ap.add_argument("--company-domain", help="your organisation's real e-mail domain")
    ap.add_argument("--json", action="store_true", help="print JSON instead of a text report")
    ap.add_argument("--dump-samples", help="write the built-in samples to a JSON file and exit")
    args = ap.parse_args()

    if args.dump_samples:
        with open(args.dump_samples, "w", encoding="utf-8") as fh:
            json.dump(SAMPLES, fh, indent=2, ensure_ascii=False)
        print(f"Wrote {len(SAMPLES)} samples to {args.dump_samples}")
        return

    messages = []
    if args.eml:
        messages.append(load_eml(args.eml))
    if args.json_in:
        with open(args.json_in, encoding="utf-8") as fh:
            data = json.load(fh)
        messages += data if isinstance(data, list) else [data]
    if args.interactive:
        messages.append(interactive())
    if args.samples or not messages:
        messages += SAMPLES

    results = []
    for m in messages:
        r = analyze(m, args.company_domain)
        results.append({"message": m, "result": r})
        if not args.json:
            print(format_report(m, r, m.get("title")))
            print()

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    elif len(messages) > 1:
        print("SUMMARY")
        for item in results:
            m, r = item["message"], item["result"]
            exp = m.get("expected")
            mark = "" if not exp else ("  [matches expected]" if exp == r["verdict"] else f"  [EXPECTED {exp}]")
            print(f"  #{m.get('id', '-')}: {r['verdict']:<10} score={r['score']:<3} -> {r['action']}{mark}")


if __name__ == "__main__":
    sys.exit(main())
