DROP DATABASE IF EXISTS phishing_db;
CREATE DATABASE phishing_db;
USE phishing_db;

CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE url_scans (
    scan_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    url TEXT NOT NULL,
    prediction VARCHAR(20) NOT NULL,
    confidence DECIMAL(5,2) NOT NULL,
    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL
);

CREATE TABLE url_features (
    feature_id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT NOT NULL,
    url_length INT, host_length INT, path_length INT, query_length INT,
    num_dots INT, num_subdomains INT, num_hyphens INT, host_hyphens INT,
    num_slashes INT, path_depth INT, num_special_chars INT, num_digits INT,
    digit_ratio DECIMAL(6,4), host_digits INT, num_params INT, num_percent INT,
    has_at TINYINT, has_ip TINYINT, has_https TINYINT, has_port TINYINT,
    num_suspicious_words INT, suspicious_tld TINYINT, is_shortener TINYINT,
    has_script_ext TINYINT, url_entropy DECIMAL(7,4),
    FOREIGN KEY (scan_id) REFERENCES url_scans(scan_id) ON DELETE CASCADE
);

CREATE INDEX idx_scans_prediction ON url_scans(prediction);
CREATE INDEX idx_scans_time ON url_scans(scanned_at);

CREATE VIEW scan_summary AS
SELECT prediction, COUNT(*) AS total_scans, ROUND(AVG(confidence), 2) AS avg_confidence
FROM url_scans
GROUP BY prediction;