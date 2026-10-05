import os
import re
import joblib
import pandas as pd
import mysql.connector
from flask import Flask, request, jsonify, render_template
from features import extract_features, host_of, DB_FEATURES

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Load the trained model bundle
bundle = joblib.load(os.path.join(BASE_DIR, "model.joblib"))
model = bundle["model"]
columns = bundle["columns"]
model_name = bundle.get("name", "Random Forest")

MAX_URL_LEN = 2000

# If a trusted domain still gets this phishing probability or higher, the model wins.
TRUSTED_OVERRIDE_THRESHOLD = 0.8

# Three-way verdict (Legitimate / Suspicious / Phishing).
# Leave False until templates/index.html can display "Suspicious" and the
# url_scans.prediction column accepts that value. Then set it to True.
ENABLE_SUSPICIOUS = False
SUSPICIOUS_LOW = 0.35    # at or below this phishing probability -> Legitimate
SUSPICIOUS_HIGH = 0.65   # at or above this phishing probability -> Phishing

HOST_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")
IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# Trusted popular domains (Tranco list). Optional: if the file is missing,
# the app still works and relies on the model alone.
TRUSTED = set()
_top_path = os.path.join(BASE_DIR, "top_domains.csv")
if os.path.exists(_top_path):
    TRUSTED = set(
        pd.read_csv(_top_path, header=None)
        .iloc[:, -1].astype(str).str.lower().head(20000)
    )
    print(f"Loaded {len(TRUSTED)} trusted domains")
else:
    print("top_domains.csv not found - running without trusted-domain check")


def is_trusted(url):
    """True if the URL's host or one of its parent domains is in the trusted list.
    mail.google.com -> trusted, google.com.evil.xyz -> not trusted."""
    parts = host_of(url).split(".")
    return any(".".join(parts[i:]) in TRUSTED for i in range(len(parts) - 1))


def get_db():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_NAME", "phishing_db"),
    )

def validate_url(url):
    if not url:
        return "Please enter a URL"
    if len(url) > MAX_URL_LEN:
        return "URL is too long"
    if any(c.isspace() for c in url):
        return "URL must not contain spaces"
    host = host_of(url)
    if not (HOST_RE.match(host) or IP_RE.match(host)):
        return "That doesn't look like a valid URL (check the domain and the http:// part)"
    return None

def save_scan(url, prediction, confidence, feats):
    db = get_db()
    try:
        cur = db.cursor()
        cur.execute(
            "INSERT INTO url_scans (url, prediction, confidence) VALUES (%s, %s, %s)",
            (url, prediction, confidence),
        )
        scan_id = cur.lastrowid

        # Only the original features go to the database (the table has no columns
        # for the newer model-only features).
        db_feats = {k: feats[k] for k in DB_FEATURES}
        cols = ", ".join(db_feats.keys())
        marks = ", ".join(["%s"] * len(db_feats))
        cur.execute(
            f"INSERT INTO url_features (scan_id, {cols}) VALUES (%s, {marks})",
            (scan_id, *db_feats.values()),
        )
        db.commit()
        cur.close()
        return scan_id
    finally:
        db.close()

def query_all(sql):
    db = get_db()
    try:
        cur = db.cursor(dictionary=True)
        cur.execute(sql)
        rows = cur.fetchall()
        cur.close()
        return rows
    finally:
        db.close()

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/predict", methods=["POST"])
def predict():
    url = (request.get_json(silent=True) or {}).get("url", "").strip()
    error = validate_url(url)
    if error:
        return jsonify({"error": error}), 400

    try:
        raw_feats = extract_features(url)

        # Build DataFrame aligned with model training columns
        X = pd.DataFrame([raw_feats])[columns].fillna(0)

        # Print matrix to terminal
        print("\n=== MATRIX PASSED TO MODEL ===")
        print(X.to_string(index=False))
        print("==============================\n")

        proba = model.predict_proba(X)[0]

        # classes_ = [0, 1] where 1 is Phishing (bad)
        phishing_prob = float(proba[1])

        if is_trusted(url) and phishing_prob < TRUSTED_OVERRIDE_THRESHOLD:
            prediction = "Legitimate"
            confidence = 99.0
        elif ENABLE_SUSPICIOUS:
            if phishing_prob >= SUSPICIOUS_HIGH:
                prediction = "Phishing"
                confidence = round(phishing_prob * 100, 2)
            elif phishing_prob <= SUSPICIOUS_LOW:
                prediction = "Legitimate"
                confidence = round((1.0 - phishing_prob) * 100, 2)
            else:
                prediction = "Suspicious"
                confidence = round(phishing_prob * 100, 2)  # risk score
        elif phishing_prob >= 0.5:
            prediction = "Phishing"
            confidence = round(phishing_prob * 100, 2)
        else:
            prediction = "Legitimate"
            confidence = round((1.0 - phishing_prob) * 100, 2)

    except Exception as e:
        print("Feature/model error:", e)
        return jsonify({"error": "Could not process this URL"}), 400

    saved, scan_id = True, None
    try:
        scan_id = save_scan(url, prediction, confidence, raw_feats)
    except Exception as e:
        saved = False
        print("Database error:", e)

    return jsonify({
        "prediction": prediction,
        "confidence": confidence,
        "phishing_probability": round(phishing_prob * 100, 2),
        "model": model_name,
        "saved_to_db": saved,
        "scan_id": scan_id,
    })

@app.route("/history")
def history():
    template_name = "scan_history.html" if os.path.exists(
        os.path.join(BASE_DIR, "templates", "scan_history.html")
    ) else "history.html"

    try:
        total = query_all("SELECT COUNT(*) AS total FROM url_scans")[0]["total"]
        by_label = query_all(
            "SELECT prediction, COUNT(*) AS count, "
            "ROUND(AVG(confidence), 2) AS avg_confidence "
            "FROM url_scans GROUP BY prediction"
        )
        recent = query_all(
            "SELECT scan_id, url, prediction, confidence, scanned_at "
            "FROM url_scans ORDER BY scan_id DESC LIMIT 10"
        )
        return render_template(
            template_name, total=total, by_label=by_label, recent=recent
        )
    except Exception as e:
        return render_template(
            template_name, error=str(e), total=0, by_label=[], recent=[]
        )

if __name__ == "__main__":
    app.run(debug=True)