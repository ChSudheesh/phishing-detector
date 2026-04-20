from flask import Flask, request, jsonify
from flask_cors import CORS
import random

# ✅ STEP 1: create app FIRST
app = Flask(__name__)
CORS(app)

# ✅ STEP 2: define route
@app.route('/predict', methods=['POST'])
def predict():
    data = request.json
    url = data['url']

    if "@" in url or "login" in url or "verify" in url:
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

# ✅ STEP 3: run app
if __name__ == "__main__":
    app.run(debug=True)
