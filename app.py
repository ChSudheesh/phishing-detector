from flask import Flask, request, jsonify
from flask_cors import CORS
import re
import math
from collections import Counter
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)

def extract_features(url):
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
        url.count('.'),
        url.count('@'),
        int(url.startswith('https')),
        entropy(hostname),
        int('login' in url.lower()),
        int('verify' in url.lower())
    ]

    return features


@app.route('/predict', methods=['POST'])
def predict():
    data = request.json
    url = data['url']

    features = extract_features(url)

    # RULE-BASED LOGIC (TEMP AI)
    score = sum(features)

    if "@" in url or "login" in url or "verify" in url or score > 50:
        result = "Phishing"
    else:
        result = "Safe"

    return jsonify({"result": result})


if __name__ == "__main__":
    app.run(debug=True)
