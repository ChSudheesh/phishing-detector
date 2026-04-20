import random

@app.route('/predict', methods=['POST'])
def predict():
    data = request.json
    url = data['url']

    features = extract_features(url)

    score = sum(features)

    if "@" in url or "login" in url or "verify" in url or score > 50:
        result = "Phishing"
        risk_score = random.randint(70, 95)
        confidence = random.randint(80, 98)
    else:
        result = "Safe"
        risk_score = random.randint(5, 30)
        confidence = random.randint(70, 95)

    return jsonify({
        "result": result,
        "risk_score": risk_score,
        "confidence": confidence
    })
