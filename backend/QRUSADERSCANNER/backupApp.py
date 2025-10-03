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

# ===============================
# Google Custom Search API
# ===============================
GOOGLE_API_KEY = "AIzaSyBFFrYMX2p6DYJ-7gkxblCO4R6GkCSWg7Y"
GOOGLE_CX_ID = "65329c65e74ab4745"

# ===============================
# Domain lists & constants
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
# Helper functions
# ===============================
def has_invalid_chars(domain):
    return int(bool(re.search(r'[^a-zA-Z0-9\.-]', domain)))

def min_similarity(domain):
    return max(SequenceMatcher(None, domain, trusted).ratio() for trusted in MAJOR_TRUSTED_DOMAINS)

def is_typo_squatting(domain, threshold=0.85):
    sim_score = min_similarity(domain)
    return int(sim_score >= threshold and domain not in MAJOR_TRUSTED_DOMAINS)

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
# Google Index check
# ===============================
def is_indexed_by_google(url):
    query = f"site:{url}"
    api_url = f"https://www.googleapis.com/customsearch/v1?q={query}&key={GOOGLE_API_KEY}&cx={GOOGLE_CX_ID}"
    try:
        resp = requests.get(api_url, timeout=10)
        data = resp.json()
        return int('items' in data)
    except Exception as e:
        print(f"Google index check error for {url}: {e}")
        return 0

# ===============================
# Feature extraction
# ===============================
def extract_features(url, whois_info=None):
    parsed = urlparse(url if url.startswith("http") else "http://" + url)
    domain = parsed.netloc.lower()
    path = parsed.path

    letters = sum(c.isalpha() for c in url)
    digits = sum(c.isdigit() for c in url)
    special_chars = sum(not c.isalnum() for c in url)

    feats = {
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
        'is_typo_squatting': is_typo_squatting(domain),
        'google_index': is_indexed_by_google(url)
    }

    if whois_info:
        feats.update(whois_info)

    return feats

def risk_level(prob_malicious):
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

@app.route('/scan', methods=['POST'])
def scan_qr():
    try:
        data = request.get_json()
        image_data = data['image'].split(',')[1]  # Remove data URI header
        image_bytes = base64.b64decode(image_data)
        image = Image.open(io.BytesIO(image_bytes))
        opencv_image = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)

        qr_codes = decode(opencv_image)
        results = []

        for qr in qr_codes:
            url = qr.data.decode('utf-8')
            whois_info = get_whois_features(url)
            feats = extract_features(url, whois_info=whois_info)
            feats_df = pd.DataFrame([feats])[feature_columns].fillna(0)

            prob = rf_model.predict_proba(feats_df)[0][1]
            risk = risk_level(prob)

            results.append({
                'url': url,
                'prediction': risk,
                'confidence': float(round(prob * 100, 2)),
                'is_malicious': bool(prob >= 0.70),
                'google_index': feats.get('google_index', 0)
            })

        return jsonify({'success': True, 'results': results, 'count': len(results)})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/analyze_url', methods=['POST'])
def analyze_url():
    try:
        data = request.get_json()
        url = data['url']

        whois_info = get_whois_features(url)
        feats = extract_features(url, whois_info=whois_info)
        feats_df = pd.DataFrame([feats])[feature_columns].fillna(0)

        prob = rf_model.predict_proba(feats_df)[0][1]
        risk = risk_level(prob)

        return jsonify({
            'success': True,
            'url': url,
            'prediction': risk,
            'confidence': float(round(prob * 100, 2)),
            'is_malicious': bool(prob >= 0.70),
            'google_index': feats.get('google_index', 0),
            'features': feats
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# ===============================
# 6️⃣ Run Flask App
# ===============================
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)