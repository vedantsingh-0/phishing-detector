import re
import requests
import tldextract
import whois
from datetime import datetime
from urllib.parse import urlparse
from bs4 import BeautifulSoup


def safe_request(url, timeout=5):
    """Try to fetch the page. Return None if it fails (site down, blocked, etc.)"""
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        return response
    except Exception:
        return None


def extract_features(url):
    features = {}

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc
    ext = tldextract.extract(url)
    full_domain = ext.domain + "." + ext.suffix if ext.suffix else ext.domain

    ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    features["UsingIP"] = -1 if re.match(ip_pattern, domain) else 1

    length = len(url)
    if length < 54:
        features["LongURL"] = 1
    elif length <= 75:
        features["LongURL"] = 0
    else:
        features["LongURL"] = -1

    shorteners = ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly", "is.gd"]
    features["ShortURL"] = -1 if any(s in url for s in shorteners) else 1

    features["Symbol@"] = -1 if "@" in url else 1

    features["Redirecting//"] = -1 if url.rfind("//") > 7 else 1

    features["PrefixSuffix-"] = -1 if "-" in ext.domain else 1

    subdomain = ext.subdomain
    dot_count = subdomain.count(".") + (1 if subdomain else 0)
    if dot_count == 0:
        features["SubDomains"] = 1
    elif dot_count == 1:
        features["SubDomains"] = 0
    else:
        features["SubDomains"] = -1

    features["HTTPS"] = 1 if parsed.scheme == "https" else -1

    # NonStdPort - is a non-standard port explicitly used in the URL?
    port = parsed.port
    if port is None or port in [80, 443]:
        features["NonStdPort"] = 1
    else:
        features["NonStdPort"] = -1

    # HTTPSDomainURL - does "https" appear misleadingly inside the domain/subdomain text?
    domain_text = (ext.subdomain + "." + ext.domain).lower()
    features["HTTPSDomainURL"] = -1 if "https" in domain_text else 1

    # DomainRegLen - via WHOIS, is domain registered for a long time (more trustworthy)?
    try:
        w = whois.whois(full_domain)
        exp_date = w.expiration_date
        if isinstance(exp_date, list):
            exp_date = exp_date[0]
        if exp_date:
            days_left = (exp_date - datetime.now()).days
            features["DomainRegLen"] = 1 if days_left > 365 else -1
        else:
            features["DomainRegLen"] = 0
    except Exception:
        features["DomainRegLen"] = 0

    response = safe_request(url)

    if response is not None and response.status_code == 200:
        html = response.text
        soup = BeautifulSoup(html, "html.parser")

        # Favicon - loaded from same domain or external?
        icon_link = soup.find("link", rel=lambda x: x and "icon" in x.lower())
        if icon_link and icon_link.get("href"):
            href = icon_link.get("href")
            if href.startswith("http") and domain not in href:
                features["Favicon"] = -1
            else:
                features["Favicon"] = 1
        else:
            features["Favicon"] = 1

        tags = soup.find_all(["img", "script", "link"])
        total = len(tags)
        external = 0
        for tag in tags:
            src = tag.get("src") or tag.get("href")
            if src and domain not in src and src.startswith("http"):
                external += 1
        if total == 0:
            features["RequestURL"] = 1
        else:
            pct = external / total
            features["RequestURL"] = 1 if pct < 0.22 else (0 if pct < 0.61 else -1)

        anchors = soup.find_all("a")
        total_a = len(anchors)
        bad_anchors = 0
        for a in anchors:
            href = a.get("href", "")
            if href in ["#", "", "javascript:void(0)"] or (href.startswith("http") and domain not in href):
                bad_anchors += 1
        if total_a == 0:
            features["AnchorURL"] = 1
        else:
            pct = bad_anchors / total_a
            features["AnchorURL"] = 1 if pct < 0.31 else (0 if pct < 0.67 else -1)

        script_link_tags = soup.find_all(["script", "link"])
        total_sl = len(script_link_tags)
        external_sl = 0
        for tag in script_link_tags:
            src = tag.get("src") or tag.get("href")
            if src and domain not in src and src.startswith("http"):
                external_sl += 1
        if total_sl == 0:
            features["LinksInScriptTags"] = 1
        else:
            pct = external_sl / total_sl
            features["LinksInScriptTags"] = 1 if pct < 0.17 else (0 if pct < 0.81 else -1)

        forms = soup.find_all("form")
        if len(forms) == 0:
            features["ServerFormHandler"] = 1
        else:
            suspicious = 0
            for form in forms:
                action = form.get("action", "")
                if action in ["", "about:blank"]:
                    suspicious += 1
                elif action.startswith("http") and domain not in action:
                    suspicious += 1
            features["ServerFormHandler"] = -1 if suspicious > 0 else 1

        features["InfoEmail"] = -1 if "mailto:" in html.lower() else 1

        features["AbnormalURL"] = 1 if ext.domain in html else -1

        redirect_count = len(response.history)
        if redirect_count <= 1:
            features["WebsiteForwarding"] = 1
        elif redirect_count <= 4:
            features["WebsiteForwarding"] = 0
        else:
            features["WebsiteForwarding"] = -1

        features["StatusBarCust"] = -1 if "onmouseover" in html.lower() else 1

        features["DisableRightClick"] = -1 if "event.button==2" in html.lower() or "contextmenu" in html.lower() else 1

        features["UsingPopupWindow"] = -1 if "alert(" in html.lower() else 1

        features["IframeRedirection"] = -1 if "<iframe" in html.lower() else 1

    else:
        features["Favicon"] = 1
        for key in ["RequestURL", "AnchorURL", "LinksInScriptTags", "ServerFormHandler",
                    "InfoEmail", "AbnormalURL", "WebsiteForwarding", "StatusBarCust",
                    "DisableRightClick", "UsingPopupWindow", "IframeRedirection"]:
            features[key] = 0

    features["AgeofDomain"] = 1
    features["DNSRecording"] = 1
    features["WebsiteTraffic"] = 0
    features["PageRank"] = 0
    features["GoogleIndex"] = 1
    features["LinksPointingToPage"] = 0
    features["StatsReport"] = 1

    return features
