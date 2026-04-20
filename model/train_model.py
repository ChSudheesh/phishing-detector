import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib
import re
import math
from collections import Counter
from urllib.parse import urlparse

# ── Same extract_features as app.py ─────────────────────────────
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

    return {
        'url_length': len(url),
        'hostname_length': len(hostname),
        'path_length': len(path),
        'num_dots': url.count('.'),
        'num_hyphens': url.count('-'),
        'num_at': url.count('@'),
        'num_slash': url.count('/'),
        'num_question': url.count('?'),
        'num_equals': url.count('='),
        'num_underscore': url.count('_'),
        'num_percent': url.count('%'),
        'num_ampersand': url.count('&'),
        'num_digits': sum(c.isdigit() for c in url),
        'digit_ratio': sum(c.isdigit() for c in url) / max(len(url), 1),
        'num_letters': sum(c.isalpha() for c in url),
        'letter_ratio': sum(c.isalpha() for c in url) / max(len(url), 1),
        'is_https': int(url.startswith('https')),
        'has_ip': int(bool(re.match(r'https?://\d+\.\d+\.\d+\.\d+', url))),
        'num_subdomains': len(hostname.split('.')) - 2 if hostname else 0,
        'hostname_entropy': entropy(hostname),
        'path_entropy': entropy(path),
        'has_port': int(bool(parsed.port)),
        'has_at_sign': int('@' in url),
        'has_double_slash': int('//' in path),
        'has_hex': int('%' in url),
        'tld_length': len(hostname.split('.')[-1]) if '.' in hostname else 0,
        'suspicious_tld': int(any(hostname.endswith(t) for t in
            ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.win', '.loan', '.click'])),
        'brand_in_url': int(any(b in url.lower() for b in
            ['paypal', 'apple', 'google', 'microsoft', 'amazon', 'facebook', 'bank', 'secure'])),
        'has_redirect': int('redirect' in url.lower() or 'url=' in url.lower()),
        'path_depth': path.count('/'),
        'query_length': len(parsed.query or ''),
        'fragment_length': len(parsed.fragment or ''),
        'has_login': int('login' in url.lower() or 'signin' in url.lower()),
        'has_verify': int('verify' in url.lower() or 'confirm' in url.lower()),
        'has_update': int('update' in url.lower() or 'secure' in url.lower()),
        'num_special': len(re.findall(r'[^a-zA-Z0-9]', url)),
        'special_ratio': len(re.findall(r'[^a-zA-Z0-9]', url)) / max(len(url), 1),
        'url_depth': url.count('/'),
        'has_www': int(hostname.startswith('www.')),
        'domain_length': len(hostname.replace('www.', '')),
        'longest_word': max((len(w) for w in re.split(r'\W+', url) if w), default=0),
        'avg_word_length': sum(len(w) for w in re.split(r'\W+', url) if w) / max(len(re.split(r'\W+', url)), 1),
        'num_uppercase': sum(c.isupper() for c in url),
        'has_title_word': int(any(w in url.lower() for w in
            ['account', 'update', 'free', 'lucky', 'winner', 'click'])),
        'shortener': int(any(s in hostname for s in
            ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly'])),
        'tld_url_length': len(url.split('.')[-1]) if '.' in url else 0,
        'long_hostname': int(len(hostname) > 30),
        'many_hyphens': int(url.count('-') > 4),
        'many_dots': int(url.count('.') > 5),
    }

# ── Load dataset ─────────────────────────────────────────────────
print("Loading dataset...")
df = pd.read_csv("phishing.csv")
print(f"Shape: {df.shape}")
print(f"Columns: {df.columns.tolist()}")

# Auto-detect URL and label columns
if 'url' in df.columns:       url_col = 'url'
elif 'URL' in df.columns:     url_col = 'URL'
else:                          url_col = df.columns[0]

if 'label' in df.columns:     label_col = 'label'
elif 'Label' in df.columns:   label_col = 'Label'
elif 'status' in df.columns:  label_col = 'status'
else:                          label_col = df.columns[-1]

print(f"Using: url='{url_col}', label='{label_col}'")

# ── Extract features ─────────────────────────────────────────────
print("Extracting features from URLs... (may take 1-2 minutes)")
X = pd.DataFrame(df[url_col].apply(extract_features).tolist())
y = df[label_col]

# Convert text labels to numbers if needed
if y.dtype == object:
    y = y.map({
        'phishing': 1, 'legitimate': 0,
        'Phishing': 1, 'Legitimate': 0,
        'bad': 1,      'good': 0,
        'malicious': 1,'benign': 0,
        '1': 1,        '0': 0,
    }).fillna(0).astype(int)

print(f"Phishing: {y.sum()} | Safe: {(y==0).sum()}")

# ── Train ────────────────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print("Training Random Forest model...")
model = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    random_state=42,
    n_jobs=-1
)
model.fit(X_train, y_train)

# ── Evaluate ─────────────────────────────────────────────────────
score = model.score(X_test, y_test)
print(f"\nAccuracy: {score:.2%}")

# ── Save ─────────────────────────────────────────────────────────
joblib.dump(model, "model.pkl")
print("Model saved to model.pkl successfully!")
print("\nNow run: python3 app.py")
