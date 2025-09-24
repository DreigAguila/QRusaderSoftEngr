import cv2
import numpy as np
from pyzbar import pyzbar
import pandas as pd
from urllib.parse import urlparse
import joblib
from collections import Counter
import re
from difflib import SequenceMatcher
import dns.resolver
import whois
import time
from datetime import datetime

# ===============================
# 1️⃣ Load trained Random Forest model
# ===============================
model_path = r"D:\QRMODELTRAINING\backend\ZFINALPKLMODEL\rf_MainQrusaderModel.pkl"
rf_package = joblib.load(model_path)
rf_model = rf_package["model"]
features = rf_package["features"]
print(f"✅ Random Forest loaded with features: {features}")

# ===============================
# 2️⃣ QRusader domain lists
# ===============================
MAJOR_TRUSTED_DOMAINS = [
    "google.com", "facebook.com", "github.com", "microsoft.com",
    "amazon.com", "apple.com", "twitter.com", "linkedin.com",
    "youtube.com", "reddit.com", "stackoverflow.com", "wikipedia.org"
]

EDUCATIONAL_DOMAINS = [
    ".edu", ".edu.ph", ".edu.au", ".edu.sg", ".edu.my", ".edu.in",
    ".ac.uk", ".edu.cn", ".edu.br", ".edu.mx", ".edu.co", ".ac.in", ".ac.jp"
]

LEGITIMATE_TLDS = [".com", ".org", ".net", ".gov", ".mil"]
SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".pw", ".gq", ".xyz", ".top", ".win", ".bid", ".loan", ".club"
]
URL_SHORTENERS = ["bit.ly", "tinyurl.com", "ow.ly", "t.co", "goo.gl"]

SUSPICIOUS_KEYWORDS = {"login", "verify", "secure", "account", "update",
                       "bank", "free", "bonus", "signin", "paypal"}

# ===============================
# 3️⃣ Helper functions
# ===============================
def has_invalid_chars(domain):
    return int(bool(re.search(r'[^a-zA-Z0-9\.-]', domain)))

def min_similarity(domain):
    return max(SequenceMatcher(None, domain, trusted).ratio() for trusted in MAJOR_TRUSTED_DOMAINS)

def is_typo_squatting(domain, threshold=0.85):
    sim_score = min_similarity(domain)
    return int(sim_score >= threshold and domain not in MAJOR_TRUSTED_DOMAINS)

def get_whois_features(url, retries=3, delay=2):
    domain = urlparse(url).netloc
    features = {
        "domain_age_days": 0,
        "domain_age_missing": 1,
        "dns_record": 0,
        "registrar_known": 0,
        "expiration_days": 0,
        "registration_length": 0,
        "whois_privacy": 0,
        "ns_count": 0
    }
    # DNS check
    try:
        dns.resolver.resolve(domain, 'A')
        features["dns_record"] = 1
    except:
        pass

    for attempt in range(retries):
        try:
            w = whois.whois(domain)
            features["registrar_known"] = 1 if w.registrar else 0
            features["domain_age_missing"] = 0

            # Creation date
            if w.creation_date:
                creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                if creation_date:
                    features["domain_age_days"] = (datetime.now() - creation_date).days

            # Expiration date
            if w.expiration_date:
                exp_date = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
                if exp_date:
                    features["expiration_days"] = (exp_date - datetime.now()).days

            # Registration length
            if w.creation_date and w.expiration_date:
                c_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                e_date = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
                if c_date and e_date:
                    features["registration_length"] = (e_date - c_date).days

            # Whois privacy
            if w.org and "privacy" in str(w.org).lower():
                features["whois_privacy"] = 1
            if w.emails and any("privacy" in str(e).lower() for e in (w.emails if isinstance(w.emails, list) else [w.emails])):
                features["whois_privacy"] = 1

            # Nameserver count
            if w.name_servers:
                features["ns_count"] = len(w.name_servers) if isinstance(w.name_servers, list) else 1

            break  # success
        except:
            if attempt < retries - 1:
                time.sleep(delay)
    return features

# ===============================
# 4️⃣ Feature extraction
# ===============================
def extract_features(url, whois_info=None):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path

    letters = sum(c.isalpha() for c in url)
    digits = sum(c.isdigit() for c in url)
    special_chars = sum(not c.isalnum() for c in url)

    features_dict = {
        'subdomain_count': max(len(domain.split('.')) - 2, 0),
        'digit_letter_ratio': digits / letters if letters else 0,
        'repeated_char_count': sum(1 for i in range(1, len(url)) if url[i] == url[i-1]),
        'query_param_count': url.count('&') + (1 if '?' in url else 0),
        'digit_special_ratio': digits / (special_chars + 1e-6),
        'max_path_segment_length': max([len(seg) for seg in path.split('/')], default=0),
        'has_ip': int(bool(re.search(r'(\d{1,3}\.){3}\d{1,3}', url))),
        'https_token': int(url.startswith('https')),
        'url_has_suspicious_keywords': int(any(kw in url.lower() for kw in SUSPICIOUS_KEYWORDS)),
        'is_trusted_domain': int(
            any(td in domain for td in MAJOR_TRUSTED_DOMAINS) or
            any(domain.endswith(ed) for ed in EDUCATIONAL_DOMAINS) or
            any(domain.endswith(tld) for tld in LEGITIMATE_TLDS)
        ),
        'is_suspicious_domain': int(any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)),
        'is_url_shortener': int(any(short in domain for short in URL_SHORTENERS)),
        'has_invalid_characters': has_invalid_chars(domain),
        'is_typo_squatting': is_typo_squatting(domain)
    }

    if whois_info:
        features_dict.update(whois_info)

    return features_dict

def risk_level(prob_malicious):
    if prob_malicious < 0.40:
        return "✅ Safe"
    elif prob_malicious < 0.70:
        return "⚠️ Medium Risk"
    else:
        return "🚨 High Risk"

# ===============================
# 5️⃣ Camera QR scanner with WHOIS
# ===============================
cap = cv2.VideoCapture(0)
print("📷 Starting camera. Show a QR code to scan...")

scanned_urls = set()
whois_cache = {}

while True:
    ret, frame = cap.read()
    if not ret:
        break

    qr_codes = pyzbar.decode(frame)
    for qr in qr_codes:
        url = qr.data.decode('utf-8')
        if url in scanned_urls:
            continue
        scanned_urls.add(url)

        domain = urlparse(url).netloc.lower()
        # Trusted shortcut
        if any(td in domain for td in MAJOR_TRUSTED_DOMAINS) or any(domain.endswith(ed) for ed in EDUCATIONAL_DOMAINS):
            prob = 0.0
            risk = "✅ Safe"
        else:
            # WHOIS in background
            if url not in whois_cache:
                whois_cache[url] = get_whois_features(url)
            X_test = pd.DataFrame([extract_features(url, whois_info=whois_cache[url])])
            X_test = X_test.reindex(columns=features, fill_value=0)
            prob = rf_model.predict_proba(X_test)[0][1]
            risk = risk_level(prob)

        # Draw QR rectangle & label
        pts = qr.polygon
        pts = [(p.x, p.y) for p in pts]
        cv2.polylines(frame, [np.array(pts, dtype=np.int32)], True, (0,255,0), 2)
        cv2.putText(frame, f"{risk}, Prob: {prob:.3f}", (pts[0][0], pts[0][1]-10),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0,0,255), 2)
        print(f"🔗 {url} --> {risk}, Prob_Malicious: {prob:.3f}")

    cv2.imshow("QR Scanner", frame)
    if cv2.waitKey(1) & 0xFF == ord('q'):
        break

cap.release()
cv2.destroyAllWindows()
