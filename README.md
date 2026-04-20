# PhishGuard AI - Phishing Detection System
### By Sudheesh Cheruvupalli

---

## How to run this project (step by step)

### Step 1 - Open Terminal on your Mac

### Step 2 - Go into this folder
```
cd /path/to/phishing-detector
```

### Step 3 - Create virtual environment
```
python3 -m venv venv
source venv/bin/activate
```

### Step 4 - Install requirements
```
pip install -r requirements.txt
```

### Step 5 - Train the model (copy your phishing.csv into the model/ folder first!)
```
cd model
python3 train_model.py
cd ..
```

### Step 6 - Run the server
```
python3 app.py
```

### Step 7 - Open the frontend
```
open frontend/index.html
```

---

## Project Structure
```
phishing-detector/
├── app.py              ← Flask AI server (the brain)
├── requirements.txt    ← All packages needed
├── frontend/
│   └── index.html      ← Beautiful UI
└── model/
    ├── train_model.py  ← Train the AI
    ├── model.pkl       ← Trained model (generated after training)
    └── phishing.csv    ← Dataset (add your own here)
```

---

## API Endpoints
- POST /predict  → Send a URL, get Safe/Suspicious/Phishing back
- GET  /health   → Check if server is running
