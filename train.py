import os
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from features import extract_features, canonicalize, host_of, save_bigram_table

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
NON_MODEL_COLS = ["has_https"]  # scheme is a dataset artifact, never a model input

print("Loading dataset...")
df = pd.read_csv(os.path.join(BASE_DIR, "dataset.csv"))
df.columns = [c.strip() for c in df.columns]

url_col = [c for c in df.columns if c.lower() == "url"][0]
label_col = [c for c in df.columns if c.lower() == "label"][0]

df = df.dropna(subset=[url_col, label_col])
df[url_col] = df[url_col].astype(str)

# ---- Labels (1 = phishing, 0 = legitimate) ----
raw_labels = df[label_col].astype(str).str.lower().str.strip()
print("Unique raw labels:", raw_labels.unique())
df["y"] = raw_labels.isin({"bad", "phishing", "malicious"}).astype(int)
assert df["y"].nunique() == 2, (
    "Label mapping produced a single class. Edit the label set above to match "
    f"your dataset's values: {raw_labels.unique()}"
)

# ---- Balanced sample ----
if len(df) > 100000:
    parts = [g.sample(n=min(len(g), 50000), random_state=42) for _, g in df.groupby("y")]
    df = pd.concat(parts, ignore_index=True)

df = df[[url_col, "y"]].rename(columns={url_col: "url"})

# ---- Augmentation 1: host-only versions, so "no path" is not a phishing signal ----
roots = df.sample(frac=0.3, random_state=1).copy()
roots["url"] = roots["url"].map(host_of)
df = pd.concat([df, roots], ignore_index=True)

# ---- Popular domains: used as legitimate examples AND to learn what real names look like ----
top_path = os.path.join(BASE_DIR, "top_domains.csv")
if os.path.exists(top_path):
    top_all = pd.read_csv(top_path, header=None).iloc[:, -1].astype(str)
    save_bigram_table(top_all.head(100000))  # writes bigrams.json, used by features.py
    print("Built domain-name model (bigrams.json) from", min(len(top_all), 100000), "popular domains")
    top = top_all.head(20000)
    df = pd.concat([df, pd.DataFrame({"url": top, "y": 0})], ignore_index=True)
    print("Added", len(top), "popular domains as legitimate")
else:
    print("TIP: add top_domains.csv (Tranco list) for better accuracy on popular and random-looking domains")

df["canon"] = df["url"].map(canonicalize)
df = df[df["canon"].str.len() > 3].drop_duplicates(subset=["canon"]).reset_index(drop=True)

print("Rows for training:", len(df))
print("Label distribution:\n", df["y"].value_counts())

print("Extracting features...")
X = pd.DataFrame([extract_features(u) for u in df["url"]]).drop(columns=NON_MODEL_COLS)
y = df["y"].values
groups = df["url"].map(host_of)

# Group split: the same host never lands in both train and test (no leakage)
gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
train_idx, test_idx = next(gss.split(X, y, groups))
X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
y_train, y_test = y[train_idx], y[test_idx]

print("Training Random Forest model...")
model = RandomForestClassifier(
    n_estimators=200,
    max_depth=25,
    min_samples_leaf=2,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1,
)
model.fit(X_train, y_train)

pred = model.predict(X_test)
tn, fp, fn, tp = confusion_matrix(y_test, pred).ravel()
print("\n=== EVALUATION RESULTS (host-grouped test set) ===")
print(f"Accuracy : {accuracy_score(y_test, pred):.4f}")
print(f"Precision: {precision_score(y_test, pred):.4f}")
print(f"Recall   : {recall_score(y_test, pred):.4f}")
print(f"F1 Score : {f1_score(y_test, pred):.4f}")
print(f"TN: {tn} | FP: {fp} | FN: {fn} | TP: {tp}")

# ---- Sanity check on realistic user input ----
print("\n=== SANITY CHECK (phishing probability) ===")
samples = [
    "google.com",
    "https://www.google.com",
    "https://www.wikipedia.org/wiki/Python_(programming_language)",
    "https://github.com/pallets/flask",
    "https://www.amazon.in",
    "https://kjijoejmpoenl.com",
    "https://xqzvbnmwkrtp.com",
    "http://paypal-secure-login.verify-account.xyz/webscr?cmd=_login",
    "http://192.168.4.5/bank/login.php",
    "http://secure-update-account.tk/confirm/password.php",
]
for u in samples:
    f = pd.DataFrame([extract_features(u)])[list(X.columns)]
    print(f"{model.predict_proba(f)[0][1]:.2f}  {u}")

joblib.dump({
    "model": model,
    "columns": list(X.columns),
    "classes": [0, 1],
    "name": "Random Forest",
}, os.path.join(BASE_DIR, "model.joblib"))

print("\nSaved model.joblib successfully!")