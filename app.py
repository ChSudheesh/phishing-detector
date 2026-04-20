from flask import Flask, request, jsonify
from flask_cors import CORS
import random

# ✅ STEP 1: create app FIRST
app = Flask(__name__)
CORS(app)

# ✅ STEP 2: HEALTH CHECK (VERY IMPORTANT)
@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"})

# ✅ STEP 3: PREDICT API
@app.route('/predict', methods=['POST'])
def predict():
    data = request.json
    url = data.get('url', '')

    # Simple logic (you can replace later with ML model)
    if "@" in url or "login" in url or "verify" in url or "secure" in url:
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

# ✅ STEP 4: RUN APP (LOCAL ONLY)
if __name__ == "__main__":
    app.run(debug=True)
