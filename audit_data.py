"""
audit_data.py
=============
Security Audit Lab - Mission Scenario & Learning Repository
------------------------------------------------------------
Contains structured scenario data, beginner-friendly learning concepts,
fictional company evidence documents, and official grading benchmarks
for the first mission: ShopEase Security Investigation.

All evidence is fictional, realistic, and internally consistent.
"""

SHOPEASE_MISSION = {
    "id": "shopease",
    "title": "ShopEase Security Investigation",
    "company_name": "ShopEase Inc.",
    "company_overview": (
        "ShopEase is a fictional online retail business with 40 employees. "
        "The company sells lifestyle and consumer goods through its web portal "
        "and mobile application. ShopEase stores sensitive customer information, "
        "including full names, delivery addresses, telephone numbers, order histories, "
        "and payment card metadata (payment gateway tokens and billing records)."
    ),
    "auditor_role": "Junior Security Auditor",
    "total_stages": 4,
    "stages": {
        1: {
            "id": 1,
            "title": "Employee Access Register",
            "subtitle": "Access Control, Least Privilege & Account Deprovisioning",
            "estimated_minutes": 15,
            
            # --- TEACHING SECTION (BEFORE INVESTIGATION) ---
            "learning": {
                "topic": "Access Control & The Principle of Least Privilege",
                "intro": (
                    "Welcome to your first audit stage! In every organization, the IT system must know "
                    "exactly who is allowed into which digital room. In cybersecurity, this is called "
                    "Access Control."
                ),
                "key_concepts": [
                    {
                        "term": "Access Control",
                        "definition": (
                            "The security practice of regulating who can view or use company resources, "
                            "such as databases, servers, email accounts, and customer records."
                        ),
                        "example": "Just like only hotel staff have master keycards to supply rooms, only authorised engineers should have administrator keys to servers."
                    },
                    {
                        "term": "The Principle of Least Privilege (PoLP)",
                        "definition": (
                            "A fundamental security rule: every user should only be given the minimum level of access "
                            "necessary to perform their specific job duties, and nothing more."
                        ),
                        "example": "A customer service specialist needs to view order status, but they should never have permission to delete databases or access the company cloud server settings."
                    },
                    {
                        "term": "Account Deprovisioning (Offboarding)",
                        "definition": (
                            "The mandatory process of immediately deactivating or deleting all accounts, permissions, "
                            "and digital access when an employee resigns, retires, or leaves the company."
                        ),
                        "example": "When an employee hands in their laptop on their last day, IT must lock their Active Directory and cloud accounts within 24 hours."
                    },
                    {
                        "term": "Dormant or Orphan Accounts",
                        "definition": (
                            "Accounts that remain active and accessible long after the owner has left the company. "
                            "Cybercriminals actively hunt for these accounts because no one is watching them, making it easy to break in unnoticed."
                        ),
                        "example": "If a former IT administrator's account is still active months after they left, an attacker could steal their old password and gain full control over the company."
                    }
                ],
                "auditor_tip": (
                    "As an auditor, always compare employee HR records (who actually works here today) "
                    "with active user accounts and privilege levels in the system register."
                )
            },

            # --- EVIDENCE DOCUMENTS ---
            "evidence": {
                "document_title": "ShopEase IT Infrastructure Audit Package: Identity & Access Register",
                "date_of_audit": "February 15, 2026",
                "prepared_by": "ShopEase HR & IT Operations Department",
                "policy_extract": {
                    "policy_id": "POL-SEC-04 (User Access Management Policy)",
                    "sections": [
                        "Section 4.1: Access rights shall be granted strictly based on job role requirements (Principle of Least Privilege).",
                        "Section 4.2 (Mandatory Deprovisioning): Human Resources must inform IT Helpdesk within 4 hours of an employee departure. IT must disable and revoke all Active Directory, VPN, and cloud administrator accounts within 24 hours of employee departure.",
                        "Section 4.5: Administrator-tier permissions (Domain Admin, Cloud Root) may only be assigned to currently active senior infrastructure personnel."
                    ]
                },
                "hr_notice": {
                    "ticket_id": "HR-TICKET-8821",
                    "date": "October 14, 2025",
                    "subject": "Departure Notification - David Chen",
                    "note": (
                        "David Chen (Senior DevOps & Systems Administrator) submitted resignation. "
                        "Effective last working day: October 14, 2025. "
                        "Forwarded to IT Helpdesk for account closure and hardware return."
                    )
                },
                "user_register": [
                    {
                        "username": "sarah.jenkins",
                        "employee_name": "Sarah Jenkins",
                        "department": "Marketing",
                        "role": "Marketing Director",
                        "account_status": "Active",
                        "privilege_level": "Standard User (CRM Read Only)",
                        "mfa_enabled": "Disabled",
                        "last_login": "2026-02-15 09:12 (Office LAN)"
                    },
                    {
                        "username": "david.chen",
                        "employee_name": "David Chen",
                        "department": "Engineering / DevOps",
                        "role": "Former Senior DevOps / SysAdmin",
                        "account_status": "ACTIVE",
                        "privilege_level": "Domain Admin & AWS Cloud Root",
                        "mfa_enabled": "Disabled",
                        "last_login": "2026-02-14 23:42 (Remote IP: 198.51.100.44)"
                    },
                    {
                        "username": "priya.patel",
                        "employee_name": "Priya Patel",
                        "department": "Customer Support",
                        "role": "Support Team Lead",
                        "account_status": "Active",
                        "privilege_level": "Standard User (Tickets & Orders Read/Write)",
                        "mfa_enabled": "Disabled",
                        "last_login": "2026-02-15 08:30 (Office LAN)"
                    },
                    {
                        "username": "marcus.vance",
                        "employee_name": "Marcus Vance",
                        "department": "Engineering",
                        "role": "Lead Frontend Developer",
                        "account_status": "Active",
                        "privilege_level": "Standard User + Git Repository Admin",
                        "mfa_enabled": "Disabled",
                        "last_login": "2026-02-15 10:15 (Office LAN)"
                    },
                    {
                        "username": "elena.rostova",
                        "employee_name": "Elena Rostova",
                        "department": "Finance",
                        "role": "Junior Accountant",
                        "account_status": "Active",
                        "privilege_level": "Standard User (QuickBooks & Invoicing)",
                        "mfa_enabled": "Disabled",
                        "last_login": "2026-02-15 08:45 (Office LAN)"
                    }
                ],
                "auditor_notes": "Note: David Chen departed ShopEase 4 months ago. His Active Directory user account remains ACTIVE and has recent logins from an external IP address."
            },

            # --- BENCHMARK SOLUTION & CRITERIA ---
            "benchmark": {
                "weakness": (
                    "An administrator account belonging to a former employee (David Chen) is still active "
                    "with Domain Admin and AWS Cloud Root privileges 4 months after resignation, representing "
                    "a failure in the offboarding/deprovisioning process."
                ),
                "evidence": (
                    "HR Ticket #HR-8821 confirms David Chen resigned on October 14, 2025. However, the User Register "
                    "shows his account 'david.chen' is still ACTIVE with 'Domain Admin & AWS Cloud Root' privileges, "
                    "and recorded a remote login on February 14, 2026 at 23:42 from IP 198.51.100.44. This directly "
                    "violates ShopEase Access Policy POL-SEC-04 Section 4.2 requiring deactivation within 24 hours."
                ),
                "risk_level": "High",
                "impact": (
                    "Anyone with access to David Chen's credentials (including David or an attacker who obtains them) "
                    "has total administrative control over the company's entire cloud infrastructure and Active Directory. "
                    "They can access or exfiltrate all customer PII, delete databases, modify e-commerce source code, "
                    "or plant ransomware without restriction."
                ),
                "recommendation": (
                    "Immediately disable David Chen's account and revoke all active sessions, API keys, and cloud credentials. "
                    "Conduct a forensic audit of all actions taken by this account since October 14, 2025. "
                    "Establish an automated offboarding workflow connecting HR and IT Helpdesk, and schedule "
                    "mandatory monthly user access reviews to identify orphan accounts."
                )
            }
        },

        2: {
            "id": 2,
            "title": "Login Security Policy",
            "subtitle": "Authentication, Multi-Factor Authentication (MFA) & Lockout Controls",
            "estimated_minutes": 15,
            
            # --- TEACHING SECTION (BEFORE INVESTIGATION) ---
            "learning": {
                "topic": "Authentication, Multi-Factor Authentication & Brute-Force Defense",
                "intro": (
                    "When users log into a system, the system must verify their identity. "
                    "Relying on just a password is one of the most common causes of corporate cyber attacks."
                ),
                "key_concepts": [
                    {
                        "term": "Single-Factor Authentication (Passwords Only)",
                        "definition": (
                            "Relying solely on one piece of information (something you know: a password). "
                            "If a password is weak, shared, leaked in a data breach, or guessed, the attacker gets immediate access."
                        ),
                        "example": "If an employee uses 'Welcome2025!' on both their personal email and work account, a breach at any external site exposes ShopEase."
                    },
                    {
                        "term": "Multi-Factor Authentication (MFA / 2FA)",
                        "definition": (
                            "Requiring two or more independent proofs of identity before granting access: "
                            "1) Something you know (password), 2) Something you have (phone app / security key), "
                            "or 3) Something you are (biometrics). MFA stops over 99% of automated credential attacks."
                        ),
                        "example": "Even if an attacker steals your password, they cannot log in without the 6-digit code sent to your authenticator app."
                    },
                    {
                        "term": "Account Lockout & Rate Limiting",
                        "definition": (
                            "A security mechanism that temporarily freezes an account or slows down requests after a set "
                            "number of incorrect password attempts (e.g., locking out for 15 minutes after 5 failed tries)."
                        ),
                        "example": "Without lockout, an automated tool can guess 1,000 passwords every second until it cracks the account."
                    },
                    {
                        "term": "Login Anomaly Alerts",
                        "definition": (
                            "Automated security notifications triggered when a login attempt occurs from an unfamiliar country, "
                            "unknown device, or outside normal business hours."
                        ),
                        "example": "Receiving an email alert saying 'New login detected from Ukraine on Linux device' allows immediate intervention."
                    }
                ],
                "auditor_tip": (
                    "Inspect the technical authentication parameters. Check if MFA is enforced, whether failed "
                    "logins trigger lockouts, and if alerts warn staff of suspicious access attempts."
                )
            },

            # --- EVIDENCE DOCUMENTS ---
            "evidence": {
                "document_title": "ShopEase Core Authentication Configuration & Gateway Audit Log",
                "date_of_audit": "February 15, 2026",
                "prepared_by": "IT Systems Administration",
                "system_settings": [
                    {"parameter": "auth.enforce_mfa", "setting_value": "DISABLED (False)", "description": "Mandatory 2-factor authentication for employees", "status": "FAIL"},
                    {"parameter": "auth.password_min_length", "setting_value": "8 characters", "description": "Minimum required characters for passwords", "status": "WARN"},
                    {"parameter": "auth.account_lockout_threshold", "setting_value": "0 (DISABLED - Unlimited Attempts)", "description": "Failed attempts before account is temporarily frozen", "status": "FAIL"},
                    {"parameter": "auth.lockout_duration_minutes", "setting_value": "0 minutes", "description": "Duration account remains locked following failed attempts", "status": "FAIL"},
                    {"parameter": "auth.suspicious_login_notifications", "setting_value": "DISABLED (False)", "description": "Email/SMS alerts sent on login from new IP or device", "status": "FAIL"},
                    {"parameter": "auth.session_idle_timeout", "setting_value": "720 hours (30 days)", "description": "Duration before inactive browser sessions expire", "status": "WARN"}
                ],
                "gateway_log_extract": (
                    "=== ShopEase Web Application Firewall & Auth Gateway Log Excerpt ===\n"
                    "Timestamp: 2026-02-14 02:15:00 UTC to 02:45:00 UTC\n"
                    "Source IP: 203.0.113.88 (Unrecognized Hosting Provider in Eastern Europe)\n"
                    "Target Endpoint: POST /api/v1/auth/login\n"
                    "Target Username: admin@shopease.local\n\n"
                    "02:15:01 [AUTH] Failed login attempt #1 for admin@shopease.local (HTTP 401)\n"
                    "02:15:02 [AUTH] Failed login attempt #2 for admin@shopease.local (HTTP 401)\n"
                    "02:15:03 [AUTH] Failed login attempt #3 for admin@shopease.local (HTTP 401)\n"
                    "... [14,280 similar failed login attempts from IP 203.0.113.88 in 30 minutes] ...\n"
                    "02:44:59 [AUTH] Failed login attempt #14,284 for admin@shopease.local (HTTP 401)\n"
                    "02:45:00 [ALERT_ENGINE] No alert generated. Account lockout disabled. IP rate limit not configured.\n"
                    "=== End Log Extract ==="
                ),
                "auditor_notes": "The company relies solely on passwords. No MFA is enforced on any staff or admin account. An external adversary executed over 14,000 password guesses without triggering account lockout or security alerts."
            },

            # --- BENCHMARK SOLUTION & CRITERIA ---
            "benchmark": {
                "weakness": (
                    "The company relies strictly on passwords with no Multi-Factor Authentication (MFA), "
                    "no account lockout mechanism (unlimited attempts allowed), and no alerts for suspicious login activity."
                ),
                "evidence": (
                    "System configuration reveals 'auth.enforce_mfa' is DISABLED, 'auth.account_lockout_threshold' is set to 0 "
                    "(unlimited attempts), and 'auth.suspicious_login_notifications' is DISABLED. The Gateway Log confirms "
                    "an external IP (203.0.113.88) launched over 14,280 consecutive brute-force password attempts against "
                    "'admin@shopease.local' without being throttled, locked out, or alerting security personnel."
                ),
                "risk_level": "High",
                "impact": (
                    "Attackers can conduct automated brute-force attacks or credential stuffing scripts until they crack "
                    "passwords. Because there is no MFA, cracking or stealing a single password gives an adversary instant, "
                    "unfettered access to internal administrative systems, employee accounts, and sensitive customer data."
                ),
                "recommendation": (
                    "1) Mandate Multi-Factor Authentication (MFA) for all employees and administrators using an authenticator app or hardware key. "
                    "2) Implement an Account Lockout Policy (e.g. lock account for 15-30 minutes after 5 consecutive failed attempts). "
                    "3) Deploy rate limiting and CAPTCHA on the login endpoint. "
                    "4) Enable automated real-time security alerts for anomalous logins from unrecognized devices or IP addresses."
                )
            }
        },

        3: {
            "id": 3,
            "title": "Data Backup and Recovery",
            "subtitle": "Backup Frequency, Network Storage Isolation & Restoration Testing",
            "estimated_minutes": 15,
            
            # --- TEACHING SECTION (BEFORE INVESTIGATION) ---
            "learning": {
                "topic": "Data Backup Strategies, The 3-2-1 Rule & Disaster Recovery",
                "intro": (
                    "Data is the lifeblood of an online store. If a hard drive fails, a technician makes a mistake, "
                    "or ransomware attacks, having reliable backups is the difference between surviving and going out of business."
                ),
                "key_concepts": [
                    {
                        "term": "Data Backup",
                        "definition": (
                            "Creating duplicate copies of databases, files, and configurations so they can be restored "
                            "if the original data is destroyed, corrupted, or encrypted."
                        ),
                        "example": "Backing up the customer database every night so you never lose more than 24 hours of transactions."
                    },
                    {
                        "term": "The 3-2-1 Backup Rule",
                        "definition": (
                            "The universally recognized gold standard in data protection: "
                            "• 3 total copies of important data (1 primary + 2 backup copies). "
                            "• 2 different storage media types (e.g., local server storage and cloud storage). "
                            "• 1 copy stored offsite or in an immutable, air-gapped environment."
                        ),
                        "example": "Keeping your database on the server, a copy on an office NAS, and an encrypted copy stored in an independent cloud vault."
                    },
                    {
                        "term": "Offsite & Immutable Backups",
                        "definition": (
                            "Backups stored in a physically separate location or in a write-once format that cannot be deleted "
                            "or encrypted by ransomware running on the local office network."
                        ),
                        "example": "If ransomware infects the office, it will encrypt everything on the local network share, but it cannot touch an air-gapped cloud backup."
                    },
                    {
                        "term": "Restoration Testing",
                        "definition": (
                            "The practice of actually testing the recovery process to verify that backup files can be opened "
                            "and restored without errors before an emergency happens."
                        ),
                        "example": "A backup that has never been tested is just a wish. Many companies discover their backups were corrupted or missing key tables only after disaster strikes."
                    }
                ],
                "auditor_tip": (
                    "Look closely at where backups are stored, how frequently they occur, and whether the company "
                    "has ever verified that they can actually restore their data from those backups."
                )
            },

            # --- EVIDENCE DOCUMENTS ---
            "evidence": {
                "document_title": "ShopEase Database Backup Architecture & Disaster Recovery Log",
                "date_of_audit": "February 15, 2026",
                "prepared_by": "IT Operations & Database Team",
                "backup_specification": {
                    "database_system": "PostgreSQL 16 (Customer Records, Orders & Payment Tokens)",
                    "database_size": "420 GB",
                    "backup_method": "Manual SQL dump (`pg_dump`) executed manually by junior IT technician",
                    "backup_frequency": "Ad-hoc / Manual (typically performed once every 3 to 6 months)",
                    "last_backup_date": "August 22, 2025 (Nearly 6 months ago)",
                    "storage_location": "\\\\shopease-nas01\\backups (Single office NAS device located in main office closet)",
                    "network_segment": "Same local subnet (192.168.1.0/24) shared with all employee workstations",
                    "offsite_cloud_copy": "NONE - Cloud backup subscription canceled in 2024 to save budget",
                    "immutable_airgap": "NONE - Share is mounted with Read/Write access across the office network",
                    "restoration_testing_history": "NEVER TESTED. No simulated restoration drills have ever been performed since deployment 18 months ago."
                },
                "incident_report": {
                    "report_id": "INC-2025-11-28",
                    "incident_title": "Black Friday Production Database Sector Crash & Permanent Data Loss",
                    "incident_date": "November 28, 2025",
                    "summary": (
                        "During the Black Friday promotional sale, the primary SSD array on the database server "
                        "suffered catastrophic sector corruption. When IT attempted to recover, the only available "
                        "backup on the office NAS was dated August 22, 2025 (over 3 months old). "
                        "Because no recent backup existed, ShopEase permanently lost approximately 3 weeks of customer orders, "
                        "shipping manifests, and product reviews. Customer service received over 400 customer complaints "
                        "and the company was forced to issue $45,000 in emergency manual refunds."
                    )
                },
                "auditor_notes": "Backups are irregular, manual, and stored on an unsegmented local network share with no offsite copy. No restoration drills have ever been conducted, and a major data loss incident has already occurred."
            },

            # --- BENCHMARK SOLUTION & CRITERIA ---
            "benchmark": {
                "weakness": (
                    "Inadequate backup and recovery practices: backups are manual and infrequent (performed every 3 to 6 months), "
                    "stored on the same local office network without offsite or immutable copies, and restoration has never been tested, "
                    "resulting in proven data loss."
                ),
                "evidence": (
                    "The Backup Specification confirms backups are manual and ad-hoc (last backup was August 22, 2025), "
                    "stored on a single local network share (\\\\shopease-nas01) with NO offsite/cloud copy and NO air-gapping. "
                    "Restoration history is recorded as 'NEVER TESTED'. Incident Report INC-2025-11-28 proves that a database failure "
                    "on Black Friday caused permanent loss of 3 weeks of customer orders and $45,000 in refunds due to lack of recent backups."
                ),
                "risk_level": "High",
                "impact": (
                    "A ransomware infection on any office laptop could spread to the local NAS and encrypt both the production "
                    "systems and all backups simultaneously. Furthermore, physical events (fire, water damage) or hardware failure "
                    "can cause catastrophic, permanent loss of customer accounts, order histories, and financial records, threatening "
                    "business survival and triggering severe regulatory penalties."
                ),
                "recommendation": (
                    "1) Implement the 3-2-1 backup strategy with automated daily incremental and weekly full backups. "
                    "2) Store an encrypted, immutable copy in an offsite cloud vault isolated from the office network. "
                    "3) Conduct quarterly restoration testing drills to verify backup recoverability and integrity. "
                    "4) Define explicit Recovery Point Objectives (RPO < 24 hours) and Recovery Time Objectives (RTO < 4 hours)."
                )
            }
        },

        4: {
            "id": 4,
            "title": "Software Updates and Maintenance",
            "subtitle": "Patch Management, Critical Vulnerabilities & Central Monitoring",
            "estimated_minutes": 15,
            
            # --- TEACHING SECTION (BEFORE INVESTIGATION) ---
            "learning": {
                "topic": "Patch Management, Software Vulnerabilities & Centralized IT Monitoring",
                "intro": (
                    "All software has security flaws. When developers find vulnerabilities, they release "
                    "security patches to fix them. Leaving computers unpatched is like leaving your front door unlocked."
                ),
                "key_concepts": [
                    {
                        "term": "Vulnerabilities & Security Patches",
                        "definition": (
                            "A vulnerability is a flaw or weakness in software code that attackers can exploit to gain unauthorized access. "
                            "A patch is an update released by the software creator that repairs the security flaw."
                        ),
                        "example": "When a security hole in Windows or Apache is discovered, Microsoft or Apache releases an update to close it."
                    },
                    {
                        "term": "CVE (Common Vulnerabilities and Exposures)",
                        "definition": (
                            "A standardized international tracking number assigned to publicly disclosed cybersecurity vulnerabilities (e.g., CVE-2021-42013). "
                            "Once a CVE is published, cybercriminals actively scan the internet searching for unpatched computers."
                        ),
                        "example": "If your web server runs software with a known CVE from 11 months ago, automated attacker bots will easily exploit it."
                    },
                    {
                        "term": "Centralized Patch Management (WSUS / MDM)",
                        "definition": (
                            "Centralized IT tools (like Microsoft Intune, WSUS, or MDM) that allow administrators to automatically "
                            "push updates to all company servers and employee laptops from a central control console."
                        ),
                        "example": "Instead of asking 40 employees to update their own laptops, the IT system updates all laptops automatically every Tuesday night."
                    },
                    {
                        "term": "Risks of Decentralized / Manual Updating",
                        "definition": (
                            "When companies rely on individual employees to manually update their computers, employees routinely "
                            "click 'Snooze' or 'Remind Me Later' for months, leaving the entire company exposed."
                        ),
                        "example": "An employee postpones updates for 6 months; an attacker infects that single laptop through a known web browser bug, then attacks the internal database."
                    }
                ],
                "auditor_tip": (
                    "Inspect the vulnerability scan report and company device management policy. Look for pending critical "
                    "security patches on servers and check whether central monitoring tools are in place."
                )
            },

            # --- EVIDENCE DOCUMENTS ---
            "evidence": {
                "document_title": "ShopEase Endpoint Management Policy & Network Vulnerability Scan",
                "date_of_audit": "February 15, 2026",
                "prepared_by": "IT Support & Network Security",
                "policy_extract": {
                    "policy_id": "POL-IT-09 (Workstation & Server Maintenance Guideline)",
                    "sections": [
                        "Section 2.1: Individual employees are responsible for installing operating system and application updates on their company laptops at their own convenience.",
                        "Section 2.4: Centralized patch management tools (e.g. WSUS, Microsoft Intune, Mobile Device Management) are currently not deployed due to licensing considerations.",
                        "Section 2.7: Production servers shall only be updated during major planned platform redesigns."
                    ]
                },
                "vulnerability_scan": [
                    {
                        "hostname": "SRV-WEB-PROD01",
                        "ip_address": "192.168.10.15",
                        "role": "Public E-Commerce Web Server",
                        "os": "Ubuntu 20.04 LTS (Kernel unpatched for 420 days)",
                        "critical_cve": "CVE-2021-42013 (CVSS 9.8 - Critical Path Traversal & Remote Code Execution in Apache HTTP Server 2.4.49/2.4.50)",
                        "patch_status": "Pending for 11 months",
                        "risk_indicator": "CRITICAL"
                    },
                    {
                        "hostname": "SRV-DB-PROD02",
                        "ip_address": "192.168.10.16",
                        "role": "Customer & Order PostgreSQL Database",
                        "os": "Windows Server 2019",
                        "critical_cve": "KB5034129 (CVSS 8.8 - High Privilege Escalation & Memory Corruption)",
                        "patch_status": "Pending for 8 months",
                        "risk_indicator": "HIGH"
                    },
                    {
                        "hostname": "Workstations Subnet (40 Laptops)",
                        "ip_address": "192.168.20.0/24",
                        "role": "Employee Laptops (Finance, Support, Marketing, Dev)",
                        "os": "Windows 10 / 11 & macOS",
                        "critical_cve": "28 of 40 laptops are running outdated browsers and missing critical OS cumulative updates from 5+ months ago",
                        "patch_status": "74% of employees admitted snoozing update prompts for over 60 days",
                        "risk_indicator": "HIGH"
                    }
                ],
                "auditor_notes": "No central patch management or update schedule exists. Core servers have critical Remote Code Execution vulnerabilities pending for nearly a year, and employee workstations are severely unpatched."
            },

            # --- BENCHMARK SOLUTION & CRITERIA ---
            "benchmark": {
                "weakness": (
                    "Absence of a centralized patch management system, lack of an enforced update schedule, "
                    "and failure to apply critical security patches across production servers and employee workstations, "
                    "leaving systems exposed to known critical vulnerabilities."
                ),
                "evidence": (
                    "Policy POL-IT-09 shows updates are left to employee convenience with NO centralized tools (WSUS/MDM) deployed. "
                    "The vulnerability scan identifies critical Remote Code Execution flaw CVE-2021-42013 (CVSS 9.8) on public web server "
                    "SRV-WEB-PROD01 pending for 11 months, database server SRV-DB-PROD02 missing critical patches for 8 months, "
                    "and 28 of 40 employee laptops pending OS updates with 74% of staff snoozing prompts for over 60 days."
                ),
                "risk_level": "High",
                "impact": (
                    "An attacker on the internet can exploit known vulnerabilities (such as CVE-2021-42013) using readily available "
                    "automated exploit code to gain remote code execution on the public web server. From there, they can pivot "
                    "to the unpatched database server, deploy ransomware, exfiltrate customer personal and payment records, "
                    "or compromise employee workstations."
                ),
                "recommendation": (
                    "1) Deploy a centralized patch management solution (e.g., Microsoft Intune, WSUS, or an RMM agent) to centrally control and monitor updates. "
                    "2) Establish a formal Patch Management Policy mandating critical security patches be tested and deployed within 14 days (or 72 hours for zero-days). "
                    "3) Immediately patch the public web server (CVE-2021-42013) and database server. "
                    "4) Enforce automated workstation update policies with mandatory reboot windows so users cannot indefinitely postpone updates."
                )
            }
        }
    }
}

def get_mission(mission_id="shopease"):
    """Returns the full mission dictionary for the given mission id."""
    if mission_id == "shopease":
        return SHOPEASE_MISSION
    return None

def get_stage(mission_id, stage_id):
    """Returns stage data by mission and stage integer."""
    mission = get_mission(mission_id)
    if mission and stage_id in mission["stages"]:
        return mission["stages"][stage_id]
    return None
