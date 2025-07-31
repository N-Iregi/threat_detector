# 🛡️ Threat Watcher CLI API

Threat Watcher is a CLI-based threat intelligence tool that interfaces with the [ThreatFox API](https://threatfox.abuse.ch/) to allow users to **query and submit Indicators of Compromise (IOCs)**. It is deployed on multiple HTTP servers behind a **load balancer** and is accessible via web browsers or `curl` with user-friendly, human-readable output.

## 🌐 Deployment Overview

- Implemented as a Python CLI server using `http.server`.
- Deployed on multiple servers (e.g., Web01, Web02) with an **HAProxy** load balancer (Lb01).
- Accepts HTTP `GET` requests and returns plain text (not JSON).
- Designed to maintain the CLI feel through HTTP endpoints.

---

## 🚀 Features

- 🔍 Query IOCs by:
  - ID
  - Keyword (IP or domain)
  - File hash (MD5, SHA1, SHA256)
  - Malware family
- 🧫 Fetch recent IOCs
- 🧠 Retrieve known malware families
- 📤 Submit new IOCs to ThreatFox
- 📃 Human-readable output (formatted plain text)

---

## 📡 Endpoints

All endpoints are `GET` requests and return plain text responses.

| Endpoint | Description |
|---------|-------------|
| `/` | Health check |
| `/recent_iocs?days=3` | Get recent IOCs from the past N days (1–7) |
| `/ioc_by_id?id=123456` | Get IOC details by ID |
| `/ioc_by_keyword?keyword=badsite.com&exact_match=true` | Search IOCs by IP/domain |
| `/ioc_by_hash?hash=<your_hash>` | Search IOC by file hash |
| `/malware_list` | Get list of known malware families |
| `/ioc_by_malware?family=ZLoader&limit=20` | Get IOCs related to a malware family |
| `/submit_ioc?...` | Submit a new IOC (see below) |

### 🧾 Submitting IOCs

Example submission format:

/submit_ioc?ioc_type=domain&iocs=malicious.site&threat_type=phishing&malware=ZLoader&confidence=85&comment=Seen+in+open+phishing+campaign


Required fields:
- `ioc_type` (domain, ip, url, md5, sha1, sha256)
- `iocs` (the actual indicator)
- `threat_type` (e.g., phishing, malware)
- `malware` (name of malware family)
- `confidence` (0–100)
- `comment` (optional)

---

## 🧪 Example Usage

Using `curl` to query IOC by ID:

```bash
curl http://localhost:8080/ioc_by_id?id=123456
Output:

🎯 IOC found by id entered:
IOC: badsite.com | Type: domain | Tags: phishing,malware
Threat type of IOC: phishing - Credential harvesting
Malware name in IOC: ZLoader
Level of malice carried: 95
...
⚙️ Setup & Deployment
1. Dependencies
Install requirements:

bash
Copy
Edit
pip install -r requirements.txt
2. Run Locally
bash
Copy
Edit
python3 main.py
Server runs by default on port 8080.

3. Docker (Optional)
If using Docker:

bash
Copy
Edit
docker build -t threatwatcher .
docker run -p 8080:8080 threatwatcher
4. HAProxy Load Balancer (Sample config)
Basic /etc/haproxy/haproxy.cfg:

cfg
Copy
Edit
frontend http_front
   bind *:80
   default_backend http_back

backend http_back
   balance roundrobin
   server web01 192.168.1.10:8080 check
   server web02 192.168.1.11:8080 check
🧠 Validation & Security
All user input is validated:

IPs, domains, hashes checked with regex

Malformed or missing parameters return clear error messages

Confidence level constrained to 0–100

No sensitive credentials are stored or transmitted

🤝 Contributing
Pull requests and suggestions are welcome! Please open issues to report bugs or request features.

📜 License
This project is licensed under the MIT License.

✉️ Author
Developed by [Your Name Here]
Bachelor of Software Engineering
Passionate about cybersecurity, threat intel, and automation.
