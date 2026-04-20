from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import re
import math
from collections import Counter
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)  # This allows your frontend HTML to talk to this server

# Load the trained model
model = joblib.load('model/model.pkl')

def extract_features(url):
    """
    Extract 50 features from a URL.
    This must match EXACTLY what train_model.py uses.
    """
    url = str(url)
    parsed = urlparse(url if url.startswith('http') else 'http://' + url)
    hostname = parsed.hostname or ''
    path = parsed.path or ''

    def entropy(s):
        if not s:
            return 0
        c = Counter(s)
        return -sum((v / len(s)) * math.log2(v / len(s)) for v in c.values())

    features = [
        len(url),
        len(hostname),
        len(path),
        url.count('.'),
        url.count('-'),
        url.count('@'),
        url.count('/'),
        url.count('?'),
        url.count('='),
        url.count('_'),
        url.count('%'),
        url.count('&'),
        sum(c.isdigit() for c in url),
        sum(c.isdigit() for c in url) / max(len(url), 1),
        sum(c.isalpha() for c in url),
        sum(c.isalpha() for c in url) / max(len(url), 1),
        int(url.startswith('https')),
        int(bool(re.match(r'https?://\d+\.\d+\.\d+\.\d+', url))),
        len(hostname.split('.')) - 2 if hostname else 0,
        entropy(hostname),
        entropy(path),
        int(bool(parsed.port)),
        int('@' in url),
        int('//' in path),
        int('%' in url),
        len(hostname.split('.')[-1]) if '.' in hostname else 0,
        int(any(hostname.endswith(t) for t in
            ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.win', '.loan', '.click'])),
        int(any(b in url.lower() for b in
            ['paypal', 'apple', 'google', 'microsoft', 'amazon', 'facebook', 'bank', 'secure'])),
        int('redirect' in url.lower() or 'url=' in url.lower()),
        path.count('/'),
        len(parsed.query or ''),
        len(parsed.fragment or ''),
        int('login' in url.lower() or 'signin' in url.lower()),
        int('verify' in url.lower() or 'confirm' in url.lower()),
        int('update' in url.lower() or 'secure' in url.lower()),
        len(re.findall(r'[^a-zA-Z0-9]', url)),
        len(re.findall(r'[^a-zA-Z0-9]', url)) / max(len(url), 1),
        url.count('/'),
        int(hostname.startswith('www.')),
        len(hostname.replace('www.', '')),
        max((len(w) for w in re.split(r'\W+', url) if w), default=0),
        sum(len(w) for w in re.split(r'\W+', url) if w) / max(len(re.split(r'\W+', url)), 1),
        sum(c.isupper() for c in url),
        int(any(w in url.lower() for w in ['account', 'update', 'free', 'lucky', 'winner', 'click'])),
        int(any(s in hostname for s in ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly'])),
        len(url.split('.')[-1]) if '.' in url else 0,
        int(len(hostname) > 30),
        int(url.count('-') > 4),
        int(url.count('.') > 5),
    ]
    return [features]


@app.route('/predict', methods=['POST'])
def predict():
    data = request.json
    url = data.get('url', '')

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    features = extract_features(url)
    prediction = model.predict(features)[0]
    probability = model.predict_proba(features)[0]

    confidence = round(float(max(probability)) * 100, 1)
    risk_score = round(float(probability[1]) * 100, 1)

    if risk_score >= 70:
        label = "Phishing"
    elif risk_score >= 35:
        label = "Suspicious"
    else:
        label = "Safe"

    return jsonify({
        "result": label,
        "confidence": confidence,
        "risk_score": risk_score,
        "url": url
    })


@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "PhishGuard AI is running!"})


if __name__ == "__main__":
    print("PhishGuard AI starting on http://127.0.0.1:5000")
    app.run(debug=True, port=5000)
