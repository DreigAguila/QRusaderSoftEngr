import os
from flask import Flask, render_template, request, jsonify
import cv2
import numpy as np
from pyzbar.pyzbar import decode
import pandas as pd
import joblib
import re, time, requests
from urllib.parse import urlparse
from difflib import SequenceMatcher
import dns.resolver
import whois
from datetime import datetime
import base64
import io
from PIL import Image
from concurrent.futures import ThreadPoolExecutor, as_completed

# ===============================
# Configure Flask paths
# ===============================
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.join(BASE_DIR, "..", "frontend")

app = Flask(
    __name__,
    template_folder=os.path.join(FRONTEND_DIR, "templates"),
    static_folder=os.path.join(FRONTEND_DIR, "static")
)

# ===============================
# Load Random Forest model
# ===============================
model_path = os.path.join(BASE_DIR, "ZFINALPKLMODEL", "rf_MainQrusaderModel.pkl")
rf_package = joblib.load(model_path)
rf_model = rf_package["model"]
feature_columns = rf_package["features"]
print(f"✅ Random Forest loaded with {len(feature_columns)} features")
print("Model classes:", rf_model.classes_)

# ===============================
# Safe Browsing API
# ===============================
SAFE_BROWSING_API_KEY = "AIzaSyBFFrYMX2p6DYJ-7gkxblCO4R6GkCSWg7Y"  # ⚠️ Replace with valid API key
SAFE_BROWSING_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"

def check_safe_browsing(url):
    body = {
        "client": {"clientId": "qrchecker", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        resp = requests.post(SAFE_BROWSING_URL, json=body, timeout=5)
        if resp.status_code == 200 and resp.json().get("matches"):
            return True
    except Exception as e:
        print(f"Safe Browsing error for {url}: {e}")
    return False

# ===============================
# Domain lists & constants
# ===============================
MAJOR_TRUSTED_DOMAINS = [
    "google.com", "facebook.com", "github.com", "microsoft.com",
    "amazon.com", "apple.com", "twitter.com", "linkedin.com",
    "youtube.com", "reddit.com", "stackoverflow.com", "wikipedia.org", "kaggle.com", "edutopia.org"
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
# Helper functions
# ===============================
def normalize_domain(domain: str) -> str:
    domain = domain.lower()
    if domain.startswith("www."):
        domain = domain[4:]
    return domain

def abnormal_url(url):
    hostname = urlparse(url).hostname
    return int(hostname not in url if hostname else 0)

def tld_length(url):
    hostname = urlparse(url).hostname
    if not hostname: return 0
    return len(hostname.split('.')[-1])

def count_digits(url): return sum(c.isdigit() for c in url)
def count_letters(url): return sum(c.isalpha() for c in url)
def url_length(url): return len(url)
def hostname_length(url): return len(urlparse(url).hostname) if urlparse(url).hostname else 0
def first_dir_length(url):
    path = urlparse(url).path
    segments = path.split('/')
    return len(segments[1]) if len(segments) > 1 else 0

def is_typo_squatting(url, trusted_domains=MAJOR_TRUSTED_DOMAINS):
    hostname = urlparse(url).hostname or ""
    max_sim = max((SequenceMatcher(None, hostname, td).ratio() for td in trusted_domains), default=0)
    return int(max_sim >= 0.85 and hostname not in trusted_domains)

def is_whitelisted(url: str) -> bool:
    domain = normalize_domain(urlparse(url).netloc)
    return any(domain.endswith(td) for td in MAJOR_TRUSTED_DOMAINS)

# ===============================
# WHOIS feature extraction
# ===============================
def get_whois_features(url, retries=2, delay=2):
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

            if w.creation_date:
                creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                if creation_date:
                    features["domain_age_days"] = (datetime.now() - creation_date).days

            if w.expiration_date:
                exp_date = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
                if exp_date:
                    features["expiration_days"] = (exp_date - datetime.now()).days

            if w.creation_date and w.expiration_date:
                c_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                e_date = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
                if c_date and e_date:
                    features["registration_length"] = (e_date - c_date).days

            if w.org and "privacy" in str(w.org).lower():
                features["whois_privacy"] = 1
            if w.emails and any("privacy" in str(e).lower() for e in (w.emails if isinstance(w.emails, list) else [w.emails])):
                features["whois_privacy"] = 1

            if w.name_servers:
                features["ns_count"] = len(w.name_servers) if isinstance(w.name_servers, list) else 1

            break
        except:
            if attempt < retries - 1:
                time.sleep(delay)
    return features

# ===============================
# Feature extraction
# ===============================
def extract_features(url, whois_info=None):
    parsed = urlparse(url if url.startswith("http") else "http://" + url)
    domain = normalize_domain(parsed.netloc)
    path = parsed.path

    letters = sum(c.isalpha() for c in url)
    digits = sum(c.isdigit() for c in url)
    special_chars = sum(not c.isalnum() for c in url)

    feats = {
        'has_ip': int(bool(re.search(r'(\d{1,3}\.){3}\d{1,3}', url))),
        'https_token': int(url.startswith('https')),
        'url_has_suspicious_keywords': int(any(kw in url.lower() for kw in SUSPICIOUS_KEYWORDS)),
        'domain_age_missing': whois_info.get("domain_age_missing", 1) if whois_info else 1,
        'dns_record': whois_info.get("dns_record", 0) if whois_info else 0,
        'registrar_known': whois_info.get("registrar_known", 0) if whois_info else 0,
        'is_trusted_domain': int(
            any(td in domain for td in MAJOR_TRUSTED_DOMAINS) or
            any(domain.endswith(ed) for ed in EDUCATIONAL_DOMAINS) or
            any(domain.endswith(tld) for tld in LEGITIMATE_TLDS)
        ),
        'is_suspicious_domain': int(any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)),
        'is_url_shortener': int(any(short in domain for short in URL_SHORTENERS)),
        'abnormal_url': abnormal_url(url),
        'is_typo_squatting': is_typo_squatting(url),
        'subdomain_count': max(len(domain.split('.')) - 2, 0),
        'digit_letter_ratio': digits / (letters + 1e-6),
        'repeated_char_count': sum(1 for i in range(1, len(url)) if url[i] == url[i-1]),
        'query_param_count': url.count('&') + (1 if '?' in url else 0),
        'digit_special_ratio': digits / (special_chars + 1e-6),
        'max_path_segment_length': max([len(seg) for seg in path.split('/')], default=0),
        'domain_age_days': whois_info.get("domain_age_days", 0) if whois_info else 0,
        'expiration_days': whois_info.get("expiration_days", 0) if whois_info else 0,
        'registration_length': whois_info.get("registration_length", 0) if whois_info else 0,
        'ns_count': whois_info.get("ns_count", 0) if whois_info else 0,
        'url_length': url_length(url),
        'hostname_length': hostname_length(url),
        'first_dir_length': first_dir_length(url),
        'tld_length': tld_length(url),
        'count_digits': count_digits(url),
        'count_letters': count_letters(url)
    }
    return feats

# ---------------------------
# Flexible Payment QR Detection (THIS IS FOR DETECTING WHETHER A QR PAYMENT IS SAFE OR NOT)
# ---------------------------
PAYMENT_PROVIDERS_KEYWORDS = {
    'paymaya': ['paymaya', 'com.paymaya.qr'],
    'gcash': ['gcash', 'com.gcash'],
    'grabpay': ['grabpay', 'grabpay-', 'grab'],
    'coinsph': ['coins.ph', 'coins'],
    'spay': ['spay', 'spay.ph'],
    'maya': ['maya']
}

def is_payment_payload(data: str) -> bool:
    s = data.strip().lower()
    
    # Standard EMV/PH PPMI QR pattern
    if s.startswith('000201') or 'ph.ppmi.p2m' in s:
        return True
    
    # Check for e-wallet keywords
    if any(keyword in s for kws in PAYMENT_PROVIDERS_KEYWORDS.values() for keyword in kws):
        return True
    
    # Numeric-only payloads (common for GCash / Maya)
    if s.isdigit() and 10 <= len(s) <= 40:
        return True
    
    # Short alphanumeric payloads (GrabPay, etc.)
    if s.isalnum() and 6 <= len(s) <= 40:
        return True
    
    return False

def parse_payment_payload(data: str) -> dict:
    s = data.strip()
    lower = s.lower()
    provider = None
    
    # Guess provider by keyword
    for prov, kws in PAYMENT_PROVIDERS_KEYWORDS.items():
        if any(k in lower for k in kws):
            provider = prov
            break
    
    # If no keyword match, try numeric payload heuristics
    if not provider:
        if s.isdigit() and 10 <= len(s) <= 40:
            provider = 'gcash/maya/coinsph'
        elif s.isalnum() and 6 <= len(s) <= 40:
            provider = 'grabpay/other'

    # Heuristic: uppercase sequences as merchant name
    import re
    candidates = re.findall(r'[A-Z][A-Z\s]{3,50}', s)
    merchant_name = max(candidates, key=len).strip() if candidates else None

    # Heuristic: search for city
    city_match = re.search(r'(manila|metro manila|quezon city|makati|cebu|davao)', lower)
    merchant_city = city_match.group(0).title() if city_match else None

    return {
        'provider': provider or 'unknown',
        'merchant_name': merchant_name or None,
        'merchant_city': merchant_city or None,
        'raw_payload': s
    }

# ===============================
# WIFI QR DETECTION
# ===============================
def is_wifi_payload(data: str) -> bool:
    return data.strip().upper().startswith("WIFI:")

def parse_wifi_payload(data: str) -> dict:
    payload = data.strip()[5:]  # remove "WIFI:"
    wifi_info = {'ssid': None, 'encryption': None, 'password': None, 'hidden': False}
    
    for part in payload.split(';'):
        if part.startswith('S:'):
            wifi_info['ssid'] = part[2:]
        elif part.startswith('T:'):
            wifi_info['encryption'] = part[2:]
        elif part.startswith('P:'):
            wifi_info['password'] = part[2:]
        elif part.startswith('H:'):
            wifi_info['hidden'] = part[2:].lower() == 'true'
    return wifi_info

def evaluate_wifi_risk(wifi_info: dict) -> str:
    ssid = wifi_info.get('ssid', '').lower()
    password = wifi_info.get('password', '')
    risk_score = 0
    
    # open networks are higher risk
    if wifi_info.get('encryption', '').upper() in ['NOPASS', '']:
        risk_score += 1
    
    # suspicious SSID keywords
    suspicious_keywords = ['freewifi', 'bank', 'paymaya', 'gcash', 'grab', 'login', 'secure']
    if any(k in ssid for k in suspicious_keywords):
        risk_score += 1
    
    # overly long passwords
    if len(password) > 64:
        risk_score += 1
    
    if risk_score == 0:
        return "✅ Safe Wi-Fi"
    elif risk_score == 1:
        return "⚠️ Medium Risk Wi-Fi"
    else:
        return "🚨 High Risk Wi-Fi"


def risk_level(prob_malicious, sb_flag=False):
    if sb_flag:
        return "🚨 Flagged by Google Safe Browsing"
    if prob_malicious < 0.40:
        return "✅ Safe"
    elif prob_malicious < 0.70:
        return "⚠️ Medium Risk"
    else:
        return "🚨 High Risk"

# ===============================
# 5️⃣ Flask Routes
# ===============================
@app.route('/')
def index():
    return render_template('index.html')  # frontend/templates/index.html

@app.route('/test_connection')
def test_connection():
    return jsonify({
        'success': True,
        'message': 'Flask backend is working!',
        'timestamp': datetime.now().isoformat()
    })

# ---------------------------
# Updated /scan route with Wi-Fi QR detection
# ---------------------------
@app.route('/scan', methods=['POST'])
def scan_qr():
    try:
        data = request.get_json()
        image_data = data['image'].split(',')[1]
        image_bytes = base64.b64decode(image_data)
        image = Image.open(io.BytesIO(image_bytes))
        opencv_image = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)

        qr_codes = decode(opencv_image)
        results = []

        for qr in qr_codes:
            raw = qr.data.decode('utf-8').strip()
            raw = raw.replace('\r', '').replace('\n', '').replace('\u200b', '')

            # Payment QR path
            if is_payment_payload(raw):
                parsed = parse_payment_payload(raw)

                results.append({
                    'url': raw,
                    'prediction': f"✅ Payment QR ({parsed['provider'].upper()})",
                    'confidence': 0.0,
                    'is_malicious': False,  # <-- force False here
                    'safe_browsing': "N/A",
                    'type': 'payment',
                    'parsed_payment': {
                        'provider': parsed['provider'],
                        'merchant': parsed['merchant_name'],
                        'city': parsed['merchant_city']
                    }
                })
                continue

            # Wi-Fi QR
            if is_wifi_payload(raw):
                wifi_info = parse_wifi_payload(raw)
                risk = evaluate_wifi_risk(wifi_info)
                results.append({
                    'url': raw,
                    'prediction': risk,
                    'confidence': 0.0,
                    'is_malicious': risk.startswith('🚨'),
                    'safe_browsing': "N/A",
                    'parsed_wifi': wifi_info
                })
                continue

            # Regular URL path
            normalized_url = raw if raw.lower().startswith('http') else "http://" + raw
            whois_info = get_whois_features(normalized_url)
            feats = extract_features(normalized_url, whois_info=whois_info)
            feats_df = pd.DataFrame([feats]).reindex(columns=feature_columns, fill_value=0)

            sb_flag = check_safe_browsing(normalized_url)
            prob = rf_model.predict_proba(feats_df)[0][1]

            if is_whitelisted(normalized_url):
                risk = "✅ Safe" if not sb_flag else "🚨 Flagged by Safe Browsing"
                prob_malicious = 0.0
                is_malicious = sb_flag
            else:
                risk = risk_level(prob, sb_flag)
                prob_malicious = float(round(prob * 100, 2))
                is_malicious = bool(prob >= 0.70 or sb_flag)

            results.append({
                'url': raw,
                'prediction': risk,
                'confidence': prob_malicious,
                'is_malicious': is_malicious,
                'safe_browsing': "⚠️ Detected" if sb_flag else "✅ Clear",
                'features': feats
            })

        return jsonify({'success': True, 'results': results, 'count': len(results)})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# ---------------------------
# Updated /analyze_url route with Wi-Fi QR detection
# ---------------------------
@app.route('/analyze_url', methods=['POST'])
def analyze_url():
    try:
        data = request.get_json()
        raw = data['url'].strip()
        raw = raw.replace('\r', '').replace('\n', '').replace('\u200b', '')

        # Payment QR
        if is_payment_payload(raw):
            parsed = parse_payment_payload(raw)

            return jsonify({
                'success': True,
                'url': raw,
                'prediction': f"✅ Payment QR ({parsed['provider'].upper()})",
                'confidence': 0.0,
                'is_malicious': False,  # <-- force False for all payment QR
                'safe_browsing': "N/A",
                'parsed_payment': {
                    'provider': parsed['provider'],
                    'merchant': parsed['merchant_name'],
                    'city': parsed['merchant_city']
                }
            })

        # Wi-Fi QR
        if is_wifi_payload(raw):
            wifi_info = parse_wifi_payload(raw)
            risk = evaluate_wifi_risk(wifi_info)
            return jsonify({
                'success': True,
                'url': raw,
                'prediction': risk,
                'confidence': 0.0,
                'is_malicious': risk.startswith('🚨'),
                'safe_browsing': "N/A",
                'parsed_wifi': wifi_info
            })

        # Regular URL path
        normalized_url = raw if raw.lower().startswith('http') else "http://" + raw
        whois_info = get_whois_features(normalized_url)
        feats = extract_features(normalized_url, whois_info=whois_info)
        feats_df = pd.DataFrame([feats]).reindex(columns=feature_columns, fill_value=0)

        sb_flag = check_safe_browsing(normalized_url)
        prob = rf_model.predict_proba(feats_df)[0][1]

        if is_whitelisted(normalized_url):
            risk = "✅ Safe" if not sb_flag else "🚨 Flagged by Safe Browsing"
            prob_malicious = 0.0
            is_malicious = sb_flag
        else:
            risk = risk_level(prob, sb_flag)
            prob_malicious = float(round(prob * 100, 2))
            is_malicious = bool(prob >= 0.70 or sb_flag)

        return jsonify({
            'success': True,
            'url': raw,
            'prediction': risk,
            'confidence': prob_malicious,
            'is_malicious': is_malicious,
            'safe_browsing': "⚠️ Detected" if sb_flag else "✅ Clear",
            'features': feats
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})




# ===============================
# 6️⃣ Run Flask App
# ===============================
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)