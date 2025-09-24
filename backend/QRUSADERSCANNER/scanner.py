import cv2
import numpy as np
from pyzbar import pyzbar
import pandas as pd
from urllib.parse import urlparse
import joblib
import math
from collections import Counter
import re

# ===============================
# 1️⃣ Load trained Random Forest model
# ===============================
model_path = r"D:\QRMODELTRAINING\ZFINALPKLMODEL\Final_rf_qrusader.pkl"
rf_package = joblib.load(model_path)
rf_model = rf_package["model"]
features = rf_package["features"]

print(f"✅ Random Forest loaded with features: {features}")

# ===============================
# 2️⃣ Trusted domains (dynamic, can expand)
# ===============================
TRUSTED_DOMAINS = {
    "gcash.com", "my.gcash.com", "paypal.com", "paymaya.com",
    "facebook.com", "twitter.com", "linkedin.com",
    "google.com", "apple.com", "amazon.com"
}

# ===============================
# 3️⃣ Helper functions
# ===============================
SUSPICIOUS_KEYWORDS = {"login", "verify", "secure", "account", "update",
                       "bank", "free", "bonus", "signin", "paypal"}

def shannon_entropy(s):
    if not s: return 0
    probs = [c/len(s) for c in Counter(s).values()]
    return -sum(p * math.log2(p) for p in probs)

# Example of simple feature extractor (adapted from your previous code)
def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path

    url_length = len(url)
    subdomain_count = max(len(domain.split('.')) - 2, 0)
    path_depth = len([p for p in path.split('/') if p])
    letters = sum(c.isalpha() for c in url)
    digits = sum(c.isdigit() for c in url)
    digit_letter_ratio = digits / letters if letters > 0 else 0
    special_chars = sum(not c.isalnum() for c in url)
    special_char_ratio = special_chars / len(url) if len(url) > 0 else 0
    repeated_char_count = sum(1 for i in range(1, len(url)) if url[i] == url[i-1])
    domain_entropy = shannon_entropy(domain)
    path_entropy = shannon_entropy(path)
    long_subdomain_length = max((len(p) for p in domain.split('.')[:-2]), default=0)
    query_param_count = url.count('&') + (1 if '?' in url else 0)
    vowel_count = sum(1 for c in url.lower() if c in 'aeiou')
    consonant_count = sum(1 for c in url.lower() if c.isalpha() and c not in 'aeiou')
    digit_special_ratio = digits / (special_chars + 1e-6)
    max_path_segment_length = max([len(seg) for seg in path.split('/')], default=0)
    has_ip = int(bool(re.search(r'(\d{1,3}\.){3}\d{1,3}', url)))
    https_token = int(url.startswith('https'))
    url_has_suspicious_keywords = int(any(kw in url.lower() for kw in SUSPICIOUS_KEYWORDS))
    has_multiple_subdomains = int(subdomain_count > 1)

    return {
        'url_length': url_length,
        'subdomain_count': subdomain_count,
        'path_depth': path_depth,
        'digit_letter_ratio': digit_letter_ratio,
        'special_char_ratio': special_char_ratio,
        'repeated_char_count': repeated_char_count,
        'domain_entropy': domain_entropy,
        'path_entropy': path_entropy,
        'long_subdomain_length': long_subdomain_length,
        'query_param_count': query_param_count,
        'vowel_count': vowel_count,
        'consonant_count': consonant_count,
        'digit_special_ratio': digit_special_ratio,
        'max_path_segment_length': max_path_segment_length,
        'has_ip': has_ip,
        'https_token': https_token,
        'url_has_suspicious_keywords': url_has_suspicious_keywords,
        'has_multiple_subdomains': has_multiple_subdomains
    }

def risk_level(prob_malicious):
    if prob_malicious < 0.40:
        return "✅ Safe"
    elif prob_malicious < 0.70:
        return "⚠️ Medium Risk"
    else:
        return "🚨 High Risk"

# ===============================
# 4️⃣ Camera QR scanner
# ===============================
cap = cv2.VideoCapture(0)
print("📷 Starting camera. Show a QR code to scan...")

scanned_urls = set()  # avoid duplicates

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

        parsed_domain = urlparse(url).netloc.lower()
        if any(parsed_domain.endswith(td) for td in TRUSTED_DOMAINS):
            risk = "✅ Safe (Trusted Domain)"
        else:
            X_test = pd.DataFrame([extract_features(url)])
            X_test = X_test.reindex(columns=features, fill_value=0)
            prob = rf_model.predict_proba(X_test)[0][1]
            risk = risk_level(prob)

        # Draw rectangle and risk label
        pts = qr.polygon
        pts = [(p.x, p.y) for p in pts]
        cv2.polylines(frame, [np.array(pts, dtype=np.int32)], True, (0,255,0), 2)
        cv2.putText(frame, f"{risk}", (pts[0][0], pts[0][1]-10),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0,0,255), 2)

        print(f"🔗 {url} --> {risk}")

    cv2.imshow("QR Scanner", frame)
    if cv2.waitKey(1) & 0xFF == ord('q'):
        break

cap.release()
cv2.destroyAllWindows()
