# Phishing URL Detector

A Flask web app that classifies a URL as **Phishing** or **Legitimate** using a Random Forest model trained on features extracted from the URL text. Every scan is saved to a MySQL database and can be reviewed on a history page.

> **Note:** The model only looks at the text of the URL. It does not visit the site or check domain age, so it is not a guarantee. Treat results as a risk indicator, not a verdict.

## Features

- Paste any URL (with or without `http://` / `www.`) and get a result with a confidence score
- 25 URL-based features (length, dots, hyphens, digits, entropy, IP address, suspicious words and TLDs, URL shorteners, etc.)
- Trusted-domain check using the Tranco top-domains list, so popular sites are not wrongly flagged (the model can still override it if it is very sure the URL is phishing)
- Input validation that rejects malformed URLs before they reach the model
- Scan history and summary statistics stored in MySQL

## How it works

1. `features.py` normalizes the URL (removes the scheme and `www.`, lowercases it) and extracts the features. The same function is used for training and prediction, so the two always match.
2. `train.py` trains a Random Forest on the labelled dataset and saves it as `model.joblib`.
3. `app.py` loads the model, validates the input, predicts, and saves the result to MySQL.

## Project structure

```
phishing-detector/
├── app.py              Flask app (prediction, history, database)
├── features.py         URL normalization and feature extraction
├── train.py            Model training and evaluation
├── schema.sql          MySQL database and tables
├── queries.sql         Example queries
├── requirements.txt    Python dependencies
├── templates/          HTML pages
├── dataset.csv         Training data (not in repo, see below)
├── top_domains.csv     Trusted domains list (not in repo, see below)
└── model.joblib        Trained model (created by train.py, not in repo)
```

## Setup

Tested with **Python 3.11** on Windows.

### 1. Clone and create a virtual environment

```
git clone <your-repo-url>
cd phishing-detector
py -3.11 -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Get the data files

These are not stored in the repo because of their size.

- **`dataset.csv`**: a CSV with two columns, `URL` and `Label`, where `Label` is `bad` (phishing) or `good` (legitimate). Place it in the project folder.
- **`top_domains.csv`** (optional but recommended): download the top-sites list from [tranco-list.eu](https://tranco-list.eu), extract it, rename the CSV to `top_domains.csv`, and place it in the project folder.

### 3. Set up the database

1. Make sure MySQL is running.
2. Create the database and tables by running `schema.sql` (in MySQL Workbench, or `mysql -u root -p < schema.sql`).
3. Set your MySQL password as an environment variable (PowerShell):

```
$env:DB_PASSWORD="your_mysql_password"
```

Optional variables: `DB_HOST` (default `localhost`), `DB_USER` (default `root`), `DB_NAME` (default `phishing_db`). Never put your password in the code.

### 4. Train the model

```
python train.py
```

This prints evaluation results and a sanity check, then saves `model.joblib`.

### 5. Run the app

```
python app.py
```

Open http://127.0.0.1:5000 in your browser.

## Results

On a test set where no domain appears in both training and testing, the model reaches roughly **83% accuracy**. This is lower than figures often seen in tutorials, because those usually split by random row, which lets the same domain leak into both sets and inflates the score.

## Limitations

- URL-text features only: well-disguised phishing links can look clean, and unusual legitimate links can look suspicious.
- The trusted-domain list covers popular sites only. Shared hosting domains on that list can be abused by attackers, which is why the model is allowed to override it.
- The training data is a snapshot, so new phishing patterns may not be recognized.

## Tech stack

Python, Flask, scikit-learn, pandas, MySQL