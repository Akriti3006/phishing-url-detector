-- 1. Count by prediction
SELECT prediction, COUNT(*) FROM url_scans GROUP BY prediction;

-- 2. Phishing URLs, most confident first
SELECT * FROM url_scans WHERE prediction = 'Phishing' ORDER BY confidence DESC;

-- 3. JOIN: scans with their features
SELECT s.url, s.prediction, s.confidence, f.url_length, f.num_dots, f.has_ip
FROM url_scans s JOIN url_features f ON s.scan_id = f.scan_id;

-- 4. JOIN + GROUP BY: average features per prediction
SELECT s.prediction, COUNT(*) AS scans,
       ROUND(AVG(f.url_length), 1) AS avg_length,
       ROUND(AVG(f.num_special_chars), 1) AS avg_special_chars
FROM url_scans s JOIN url_features f ON s.scan_id = f.scan_id
GROUP BY s.prediction;

-- 5. HAVING: days with more than 3 scans
SELECT DATE(scanned_at) AS day, COUNT(*) AS total
FROM url_scans GROUP BY DATE(scanned_at) HAVING COUNT(*) > 3;

-- 6. Subquery: scans with above-average confidence
SELECT url, prediction, confidence FROM url_scans
WHERE confidence > (SELECT AVG(confidence) FROM url_scans);

-- 7. View
SELECT * FROM scan_summary;

-- 8. Index in action
EXPLAIN SELECT * FROM url_scans WHERE prediction = 'Phishing';