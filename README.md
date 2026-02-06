🛡️ Ransomware Detection, Prevention \& Honeypot System

📌 Project Overview



This project is a host-based ransomware detection and prevention system integrated with a honeypot environment, machine learning assistance, and a SOC-style dashboard.

The system continuously monitors file system activity, process behavior, network events, and web-triggered actions to detect ransomware at an early stage and prevent large-scale file encryption.



Unlike traditional signature-based antivirus solutions, this project focuses on behavioural analysis, rule-based detection, YARA signatures, heuristic scoring, and ML-assisted classification to detect both known and unknown ransomware variants.



🎯 Key Objectives



Early detection of ransomware behaviour



Real-time monitoring of files, processes, and web activity



Prevention of unauthorized file encryption



Isolation of malicious files using quarantine



Visualization of security events using a SOC dashboard



Secure access using authentication



Academic and practical demonstration of ransomware defense techniques



🧠 System Architecture (High Level)



Monitoring Layer – Captures file, process, and web events



Detection Layer – Applies rules, YARA, heuristics, and ML



Prevention Layer – Terminates processes, blocks files \& network access



Honeypot Layer – Traps and analyzes suspicious activity



Dashboard Layer – Visualizes alerts and events in real time



📂 Project Structure

Ransomware\_Project\_Final/

│

├── app/

│   ├── api/

│   │   ├── block\_api.py

│   │   ├── map\_api.py

│   │   └── server.py

│   │

│   ├── config/

│   │   └── alert\_config.json

│   │

│   ├── ml/

│   │   ├── create\_dataset.py

│   │   ├── feature\_extractor.py

│   │   ├── train\_model.py

│   │   ├── model\_predict.py

│   │   └── models/

│   │       ├── loader.py

│   │       └── .gitkeep

│   │

│   ├── monitor/

│   │   ├── alerts.py

│   │   ├── config.py

│   │   ├── event\_emit.py

│   │   ├── handlers\_os.py

│   │   ├── handlers\_web.py

│   │   ├── lifecycle.py

│   │   ├── logger.py

│   │   ├── main.py

│   │   ├── sandbox\_heuristics.py

│   │   ├── utils.py

│   │   ├── watchers.py

│   │   └── yara\_engine.py

│   │

│   ├── prevention/

│   │   ├── file\_guard.py

│   │   ├── integrity\_monitor.py

│   │   ├── net\_guard.py

│   │   ├── process\_guard.py

│   │   ├── quarantine.py

│   │   ├── sandbox\_engine.py

│   │   ├── config.py

│   │   └── utils.py

│   │

│   └── app.py

│

├── auth\_system/

│   ├── auth\_app.py

│   ├── utils.py

│   ├── templates/

│   ├── static/

│   └── requirements.txt

│

├── rules/

│   ├── falco\_rules\_custom.yaml

│   └── suricata\_ransom.rules

│

├── yara/

│   └── yara\_ransom.yar

│

├── static/

│   ├── dashboard/

│   │   ├── css/

│   │   ├── js/

│   │   └── libs/

│   └── dashboard\_soc.html

│

├── testing\_codes/

│   ├── fake\_ransom\_test.py

│   ├── fake\_ransom\_trigger.py

│   └── test.py

│

├── honeypot\_events\_queue.jsonl

├── requirements.txt

├── .gitignore

└── README.md



🔍 Detection Techniques Used

🔹 Rule-Based Detection



Detects abnormal file access patterns



Monitors rapid file modifications and encryption-like behavior



🔹 YARA Signature Detection



Uses yara/yara\_ransom.yar



Detects known ransomware patterns



🔹 Heuristic \& Sandbox Analysis



Scores suspicious behavior



Analyzes entropy, file size, execution patterns



🔹 Machine Learning Assistance



Feature extraction from files



ML model trained using labeled ransomware datasets



Reduces false positives



🛑 Prevention \& Response Mechanisms



Malicious process termination



File access blocking



File integrity monitoring



Network blocking (IP-based)



Quarantine of suspicious files



Alert generation \& logging



📊 SOC Dashboard Features



Real-time event monitoring



Ransomware alerts



File, process \& network event logs



Blocked IP list



Threat map visualization



WebSocket-based live updates



🔐 Authentication



Secure login \& registration



Token-based access control



Prevents unauthorized dashboard access



🚀 How to Run the Project (Actual Execution Flow)

1️⃣ Activate Virtual Environment



Make sure your virtual environment is created beforehand.



source venv\_app/bin/activate





This ensures all project dependencies are isolated and correctly loaded.



2️⃣ Start Authentication System



Navigate to the authentication module and start the auth service:



cd auth\_system

python3 auth\_app.py





This module:



Handles login \& registration



Generates and verifies authentication tokens



Secures access to APIs and dashboard



3️⃣ Start Backend API Server



From the project root directory, run:



uvicorn app.api.server:app --host 0.0.0.0 --port 8000 --reload





This starts:



REST APIs for alerts, blocked events, and map data



Backend services for dashboard communication



4️⃣ Launch Core Application



Run the main application module:



python3 -m app.app





This initializes:



Core orchestration logic



Integration between monitor, prevention, and APIs



5️⃣ Start Monitoring Engine



To enable real-time ransomware monitoring:



python3 -m app.monitor.main --debug





This activates:



File system monitoring



Process \& network tracking



YARA scanning



Heuristic and sandbox analysis



Alert generation



🧪 Optional: Testing \& Simulation



To validate detection logic, use test scripts:



python3 testing\_codes/fake\_ransom\_test.py

python3 testing\_codes/fake\_ransom\_trigger.py





These scripts simulate ransomware-like behavior for testing purposes.



⚠️ Execution Notes



Run monitoring components with appropriate permissions.



Recommended environment: Linux / Kali Linux.



This project is intended strictly for academic and defensive cybersecurity research.

