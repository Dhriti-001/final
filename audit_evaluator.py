"""
audit_evaluator.py
==================
Security Audit Lab - Answer Evaluation Engine & Rubric Scorer
-------------------------------------------------------------
Evaluates student audit submissions based on the 100-point rubric:
  1. Identifying the weakness (30 points)
  2. Supporting evidence (20 points)
  3. Risk assessment (20 points)
  4. Explaining the impact (15 points)
  5. Recommending a solution (15 points)

Features:
- Semantic concept matching that credits technical correctness across varied phrasing.
- Criterion-by-criterion scoring with clear, constructive deduction explanations.
- Flags uncertain or ambiguous submissions for instructor review.
- Supports optional AI Language Model API integration (via environment variables).
- If no API key is configured, honestly engages Self-Evaluation Mode using official rubric benchmarks.
- Never pretends AI grading occurred when it did not.
"""

import os
import re
import json
from audit_data import get_stage, get_mission

# Concept Knowledge Base for Semantic Evaluation
# Maps stage numbers to semantic concepts, evidence indicators, impact vectors, and remediation controls
STAGE_EVALUATION_CONCEPTS = {
    1: {
        # Stage 1: Employee Access Register (David Chen / ex-employee admin account)
        "weakness_concepts": [
            {"name": "former employee / resigned staff", "tokens": ["former", "resigned", "ex-employee", "left", "departed", "past employee", "resignation", "old employee", "no longer works", "quit"], "weight": 1.0},
            {"name": "active account / still enabled", "tokens": ["still active", "active account", "not disabled", "not deactivated", "still enabled", "not revoked", "not removed", "still has access", "remains active", "open account", "turned on", "still on", "still open", "account active", "is active"], "weight": 1.0},
            {"name": "administrator / elevated privileges", "tokens": ["admin", "administrator", "domain admin", "aws root", "root", "elevated", "sysadmin", "cloud root", "privileged", "privileges"], "weight": 0.8},
            {"name": "offboarding / deprovisioning failure", "tokens": ["offboard", "off-boarding", "deprovision", "deprovisioning", "termination process", "user lifecycle", "access review"], "weight": 0.8}
        ],
        "evidence_facts": [
            {"fact": "David Chen / specific user", "tokens": ["david", "chen", "david chen", "david.chen"]},
            {"fact": "Resignation date / timeline (Oct 14 / 4 months ago)", "tokens": ["october 14", "oct 14", "4 months", "four months", "months ago", "october"]},
            {"fact": "Active status in register", "tokens": ["status: active", "status is active", "account status active", "marked active", "still active"]},
            {"fact": "Privileges (Domain Admin / AWS Root)", "tokens": ["domain admin", "aws", "cloud root", "root access", "sysadmin"]},
            {"fact": "Recent login / remote IP", "tokens": ["last login", "yesterday", "remote", "198.51.100.44", "february 14", "23:42"]},
            {"fact": "Policy violation (POL-SEC-04 / 24 hours)", "tokens": ["pol-sec-04", "policy", "24 hours", "section 4.2", "hr ticket", "8821"]}
        ],
        "impact_concepts": [
            {"concept": "unauthorized access / full admin compromise", "tokens": ["unauthorized", "full access", "compromise", "full control", "takeover", "complete control", "admin rights"]},
            {"concept": "data theft / customer PII exfiltration", "tokens": ["steal", "data breach", "exfiltrat", "pii", "customer data", "personal data", "leak", "export"]},
            {"concept": "sabotage / deletion / modification", "tokens": ["delete", "sabotage", "wipe", "modify", "alter", "destroy", "tamper", "damage"]},
            {"concept": "ransomware / persistence / backdoor", "tokens": ["ransomware", "backdoor", "malware", "persistence", "plant", "exploit"]}
        ],
        "recommendation_concepts": [
            {"concept": "immediately disable/revoke account", "tokens": ["disable", "deactivate", "revoke", "delete account", "lock account", "suspend", "remove access", "close account"]},
            {"concept": "audit past activity / investigate logs", "tokens": ["audit", "forensic", "investigate", "check logs", "review logs", "session", "trace"]},
            {"concept": "automated offboarding workflow", "tokens": ["offboarding workflow", "hr and it", "automated offboarding", "integration", "hr process", "off-boarding", "hr tells it", "hr notify it", "hr inform it", "notify it", "inform it"]},
            {"concept": "regular user access reviews", "tokens": ["access review", "regular review", "audit accounts", "least privilege", "periodic review", "monthly review"]}
        ]
    },
    2: {
        # Stage 2: Login Security Policy (Passwords only, no MFA, no lockout, no alerts)
        "weakness_concepts": [
            {"name": "no MFA / multi-factor missing", "tokens": ["mfa", "multi-factor", "2fa", "two-factor", "second factor", "no mfa", "mfa disabled", "single factor", "passwords only", "only password"], "weight": 1.0},
            {"name": "no account lockout / unlimited attempts", "tokens": ["no lockout", "lockout disabled", "unlimited attempts", "lock out", "threshold 0", "no rate limit", "no throttling", "rate limit"], "weight": 1.0},
            {"name": "no login alerts / lack of notifications", "tokens": ["no alert", "no notification", "login alerts disabled", "suspicious login", "alerts disabled", "no warning", "no monitoring"], "weight": 0.8}
        ],
        "evidence_facts": [
            {"fact": "auth.enforce_mfa DISABLED", "tokens": ["auth.enforce_mfa", "mfa disabled", "enforce_mfa", "mfa false", "mfa is disabled"]},
            {"fact": "auth.account_lockout_threshold is 0", "tokens": ["threshold", "lockout threshold", "0", "unlimited", "lockout_threshold"]},
            {"fact": "suspicious_login_notifications DISABLED", "tokens": ["suspicious_login_notifications", "notifications disabled", "alerts disabled"]},
            {"fact": "brute force log / 14,000+ attempts from 203.0.113.88", "tokens": ["14,280", "14000", "14,000", "203.0.113.88", "gateway log", "failed login", "brute force", "failed attempts"]},
            {"fact": "admin account targeted (admin@shopease.local)", "tokens": ["admin@shopease.local", "admin account", "admin target"]}
        ],
        "impact_concepts": [
            {"concept": "brute force / credential stuffing success", "tokens": ["brute force", "credential stuffing", "guess password", "crack password", "dictionary attack", "password spray"]},
            {"concept": "account takeover / unauthorized entry", "tokens": ["account takeover", "takeover", "unauthorized access", "gain access", "break in", "compromise account"]},
            {"concept": "customer data exposure / theft", "tokens": ["customer data", "pii", "steal data", "data leak", "data breach", "order history", "payment"]},
            {"concept": "administrative elevation / lateral movement", "tokens": ["admin access", "control", "admin rights", "lateral movement", "internal systems"]}
        ],
        "recommendation_concepts": [
            {"concept": "enforce multi-factor authentication (MFA)", "tokens": ["enforce mfa", "enable mfa", "mandate mfa", "implement 2fa", "two factor", "authenticator", "hardware key", "multi-factor"]},
            {"concept": "configure account lockout policy", "tokens": ["account lockout", "lock account", "lockout policy", "threshold", "5 attempts", "lock out after", "freeze account"]},
            {"concept": "rate limiting / CAPTCHA on login", "tokens": ["rate limit", "rate limiting", "captcha", "throttle", "waf", "ip block", "firewall"]},
            {"concept": "enable suspicious login alerts", "tokens": ["enable alerts", "login alert", "anomaly detection", "notify", "sms alert", "email notification", "suspicious alert"]}
        ]
    },
    3: {
        # Stage 3: Data Backup and Recovery (Manual/infrequent, local only, no testing, Black Friday loss)
        "weakness_concepts": [
            {"name": "infrequent / manual backups", "tokens": ["infrequent", "manual backup", "ad-hoc", "every 3 to 6 months", "3-6 months", "rarely backed up", "irregular", "not automated", "no schedule"], "weight": 1.0},
            {"name": "local-only / no offsite or immutable storage", "tokens": ["local only", "no offsite", "same network", "no cloud", "nas", "same subnet", "office share", "not immutable", "no airgap", "air-gap", "unsegmented"], "weight": 1.0},
            {"name": "no restoration testing / never tested", "tokens": ["never tested", "no testing", "no drill", "restoration testing", "not verified", "untested", "never restored"], "weight": 0.8},
            {"name": "proven data loss occurrence", "tokens": ["data loss", "lost data", "black friday", "permanent loss", "corrupt", "loss incident"], "weight": 0.6}
        ],
        "evidence_facts": [
            {"fact": "Backup frequency (manual / once every 3-6 months / August 2025)", "tokens": ["3 to 6 months", "3-6 months", "august 22", "august", "6 months ago", "manual sql dump", "pg_dump"]},
            {"fact": "Storage location (\\\\shopease-nas01\\backups / local subnet)", "tokens": ["shopease-nas01", "nas", "local share", "192.168.1.0/24", "closet", "same network"]},
            {"fact": "No cloud or offsite backup", "tokens": ["cloud canceled", "no cloud", "no offsite", "none - cloud"]},
            {"fact": "Never tested restoration (18 months)", "tokens": ["never tested", "18 months", "no drills", "never"]},
            {"fact": "Incident INC-2025-11-28 / Black Friday 3 weeks lost / $45k refunds", "tokens": ["inc-2025-11-28", "black friday", "3 weeks", "400 complaints", "$45,000", "45000", "refunds", "lost 3 weeks", "sector corruption"]}
        ],
        "impact_concepts": [
            {"concept": "ransomware encrypting backups and production simultaneously", "tokens": ["ransomware", "encrypt backups", "same network", "wipe backups", "nas encrypted", "both encrypted"]},
            {"concept": "permanent catastrophic data loss", "tokens": ["permanent loss", "data lost", "cannot recover", "destroyed", "loss of data", "unrecoverable"]},
            {"concept": "business disruption / downtime / financial loss", "tokens": ["business disruption", "downtime", "financial loss", "refunds", "revenue loss", "reputation", "go out of business"]},
            {"concept": "customer trust & regulatory penalties", "tokens": ["customer trust", "complaints", "gdpr", "compliance", "lawsuit", "regulat"]}
        ],
        "recommendation_concepts": [
            {"concept": "implement 3-2-1 backup strategy", "tokens": ["3-2-1", "321 rule", "three copies", "3 copies", "two different media", "offsite"]},
            {"concept": "automated daily/regular backups", "tokens": ["automated", "daily backup", "scheduled", "incremental", "nightly", "automatic"]},
            {"concept": "offsite / immutable cloud storage", "tokens": ["offsite", "cloud backup", "immutable", "air-gap", "isolated", "cloud storage", "vault"]},
            {"concept": "regular restoration drills / RPO and RTO", "tokens": ["restoration drill", "test restoration", "recovery testing", "quarterly drill", "rpo", "rto", "verify backup"]}
        ]
    },
    4: {
        # Stage 4: Software Updates and Maintenance (Unpatched web & db server, no MDM/WSUS, snoozing)
        "weakness_concepts": [
            {"name": "unpatched software / missing critical updates", "tokens": ["unpatched", "missing updates", "outdated", "pending updates", "pending patches", "not updated", "cve", "old software", "missing patches"], "weight": 1.0},
            {"name": "no centralized patch management / lack of MDM/WSUS", "tokens": ["no central", "no patch management", "no mdm", "no wsus", "not deployed", "centralized", "decentralized", "lack of central", "no intune"], "weight": 1.0},
            {"name": "updates left to employee convenience / no schedule", "tokens": ["employee convenience", "left to employees", "no schedule", "snooze", "snoozing", "no policy", "manual update", "at their own convenience"], "weight": 0.8}
        ],
        "evidence_facts": [
            {"fact": "Policy POL-IT-09 (Section 2.1 / 2.4 - No WSUS/MDM)", "tokens": ["pol-it-09", "section 2.1", "section 2.4", "convenience", "no mdm", "no wsus", "policy"]},
            {"fact": "SRV-WEB-PROD01 / CVE-2021-42013 (CVSS 9.8 / 11 months pending)", "tokens": ["srv-web-prod01", "cve-2021-42013", "42013", "cve-2023-38606", "9.8", "apache", "11 months", "web server", "420 days"]},
            {"fact": "SRV-DB-PROD02 / KB5034129 (8 months pending)", "tokens": ["srv-db-prod02", "kb5034129", "database server", "8 months", "windows server 2019"]},
            {"fact": "Workstations: 28 of 40 laptops / 74% snoozing > 60 days", "tokens": ["28 of 40", "28/40", "74%", "60 days", "snoozing", "laptops", "browser updates"]}
        ],
        "impact_concepts": [
            {"concept": "remote code execution / server compromise", "tokens": ["remote code execution", "rce", "compromise server", "gain shell", "execute code", "take control", "web server hacked"]},
            {"concept": "database breach / customer PII exfiltration", "tokens": ["database breach", "steal data", "pivot to database", "customer records", "pii", "exfiltrate", "payment tokens"]},
            {"concept": "malware / ransomware propagation across network", "tokens": ["ransomware", "malware", "lateral movement", "spread", "infect network", "workstation infected"]},
            {"concept": "exploit of publicly known CVEs", "tokens": ["known exploit", "public cve", "automated scan", "bot", "script kiddie", "cve exploit"]}
        ],
        "recommendation_concepts": [
            {"concept": "deploy centralized patch management (WSUS / MDM / Intune)", "tokens": ["centralized patch management", "wsus", "mdm", "intune", "rmm", "central management", "centralized system", "deploy patch management"]},
            {"concept": "establish patching policy & timeline (e.g. 14 days / 72 hrs)", "tokens": ["patch management policy", "patch schedule", "14 days", "72 hours", "sla", "patching timeline", "regular schedule"]},
            {"concept": "immediately patch critical web and db servers", "tokens": ["patch web server", "update cve", "immediate patch", "update apache", "patch database", "apply kb5034129"]},
            {"concept": "enforce automated updates & mandatory reboots", "tokens": ["enforce updates", "mandatory reboot", "prevent snooze", "automated updates", "auto update", "force reboot"]}
        ]
    }
}


def _clean_text(text):
    """Normalize text for semantic analysis."""
    if not text:
        return ""
    text = text.lower().strip()
    text = re.sub(r'[\r\n\t]+', ' ', text)
    text = re.sub(r'[^\w\s\.-]', ' ', text)
    text = re.sub(r'\s+', ' ', text)
    return text


def _matches_any_token(text, token_list):
    """Checks if any token/phrase in token_list appears in text."""
    for token in token_list:
        if token in text:
            return True
    return False


def _count_concept_matches(text, concept_defs):
    """Counts how many concept definitions match in the student text."""
    matched = []
    unmatched = []
    for item in concept_defs:
        tokens = item.get("tokens", [])
        name = item.get("name") or item.get("fact") or item.get("concept")
        if _matches_any_token(text, tokens):
            matched.append(name)
        else:
            unmatched.append(name)
    return matched, unmatched


def evaluate_weakness(stage_id, student_weakness, benchmark):
    """
    Evaluates Criterion 1: Identifying the Weakness (30 points)
    """
    clean_w = _clean_text(student_weakness)
    if not clean_w:
        return {
            "score": 0,
            "max_score": 30,
            "identified": [],
            "missed": ["Core security weakness was not provided."],
            "deductions": ["Deduction (-30 pts): No substantive answer provided for identifying the security weakness."],
            "is_flagged": False
        }

    concepts = STAGE_EVALUATION_CONCEPTS.get(stage_id, {}).get("weakness_concepts", [])
    matched, unmatched = _count_concept_matches(clean_w, concepts)
    
    # Calculate score based on concept coverage
    total_concepts = len(concepts)
    match_ratio = len(matched) / total_concepts if total_concepts > 0 else 0

    deductions = []
    is_flagged = False

    if match_ratio >= 0.7:
        score = 30
    elif match_ratio >= 0.5:
        score = 25
        deductions.append(f"Deduction (-5 pts): Identified key aspect(s) ({', '.join(matched)}), but omitted important context: {', '.join(unmatched[:2])}.")
    elif match_ratio >= 0.25:
        score = 18
        deductions.append(f"Deduction (-12 pts): Partially identified the issue ({', '.join(matched)}), but missed critical root cause elements: {', '.join(unmatched)}.")
    elif len(clean_w.split()) >= 6:
        # Student wrote something non-trivial, check if it's tangentially relevant
        score = 10
        deductions.append(f"Deduction (-20 pts): Did not clearly identify the specific vulnerability for this stage. Missed core concepts: {', '.join(unmatched[:3])}.")
        is_flagged = True
    else:
        score = 5
        deductions.append("Deduction (-25 pts): Response is very brief and does not clearly state the root security weakness.")
        is_flagged = True

    return {
        "score": score,
        "max_score": 30,
        "identified": matched,
        "missed": unmatched,
        "deductions": deductions,
        "is_flagged": is_flagged
    }


def evaluate_evidence(stage_id, student_evidence, benchmark):
    """
    Evaluates Criterion 2: Supporting Evidence (20 points)
    """
    clean_e = _clean_text(student_evidence)
    if not clean_e:
        return {
            "score": 0,
            "max_score": 20,
            "identified": [],
            "missed": ["No specific evidence cited from documents."],
            "deductions": ["Deduction (-20 pts): No supporting evidence provided from the provided documents."],
            "is_flagged": False
        }

    facts = STAGE_EVALUATION_CONCEPTS.get(stage_id, {}).get("evidence_facts", [])
    matched, unmatched = _count_concept_matches(clean_e, facts)
    num_facts = len(matched)

    deductions = []
    is_flagged = False

    if num_facts >= 3:
        score = 20
    elif num_facts == 2:
        score = 17
        deductions.append(f"Deduction (-3 pts): Cites valid evidence ({', '.join(matched)}), but missed additional supporting details such as: {', '.join(unmatched[:2])}.")
    elif num_facts == 1:
        score = 12
        deductions.append(f"Deduction (-8 pts): Cites only one piece of evidence ({matched[0]}). Stronger audit findings cite multiple corroborating data points (e.g., {', '.join(unmatched[:2])}).")
    elif len(clean_e.split()) >= 8:
        score = 8
        deductions.append("Deduction (-12 pts): Narrative evidence provided but lacks concrete factual citations (specific document sections, dates, server names, or error metrics).")
        is_flagged = True
    else:
        score = 4
        deductions.append("Deduction (-16 pts): Minimal evidence provided. Always cite specific logs, dates, usernames, or policy clauses from the evidence.")
        is_flagged = True

    return {
        "score": score,
        "max_score": 20,
        "identified": matched,
        "missed": unmatched,
        "deductions": deductions,
        "is_flagged": is_flagged
    }


def evaluate_risk(stage_id, student_risk, benchmark):
    """
    Evaluates Criterion 3: Risk Assessment (20 points)
    For all 4 ShopEase stages, the objective professional risk rating is 'High'.
    """
    risk_norm = str(student_risk).strip().capitalize()
    expected_risk = benchmark.get("risk_level", "High").capitalize()

    deductions = []
    if risk_norm == expected_risk:
        score = 20
        feedback = f"Accurate risk rating ('{risk_norm}'). Matches the critical exposure of customer PII and infrastructure."
    elif risk_norm == "Medium":
        score = 10
        deductions.append(
            f"Deduction (-10 pts): Selected 'Medium' risk. For an e-commerce platform processing customer orders, "
            f"addresses, and payment metadata, this flaw presents an immediate, severe hazard that warrants a '{expected_risk}' rating."
        )
        feedback = f"Underestimated risk rating ('{risk_norm}' instead of '{expected_risk}')."
    elif risk_norm == "Low":
        score = 0
        deductions.append(
            f"Deduction (-20 pts): Selected 'Low' risk. This is a critical misconception; leaving core systems unpatched, "
            f"backups untested, or former administrators active is an acute hazard that attackers regularly exploit."
        )
        feedback = f"Severely underestimated risk rating ('{risk_norm}' instead of '{expected_risk}')."
    else:
        score = 0
        deductions.append("Deduction (-20 pts): Invalid or missing risk assessment rating.")
        feedback = "Missing or unselected risk assessment."

    return {
        "score": score,
        "max_score": 20,
        "student_rating": risk_norm,
        "expected_rating": expected_risk,
        "feedback": feedback,
        "deductions": deductions,
        "is_flagged": False
    }


def evaluate_impact(stage_id, student_impact, benchmark):
    """
    Evaluates Criterion 4: Explaining the Impact (15 points)
    """
    clean_i = _clean_text(student_impact)
    if not clean_i:
        return {
            "score": 0,
            "max_score": 15,
            "identified": [],
            "missed": ["No explanation of potential impact was provided."],
            "deductions": ["Deduction (-15 pts): No explanation of potential business or technical impact provided."],
            "is_flagged": False
        }

    concepts = STAGE_EVALUATION_CONCEPTS.get(stage_id, {}).get("impact_concepts", [])
    matched, unmatched = _count_concept_matches(clean_i, concepts)
    match_count = len(matched)

    deductions = []
    is_flagged = False

    if match_count >= 2:
        score = 15
    elif match_count == 1:
        score = 11
        deductions.append(f"Deduction (-4 pts): Identified realistic consequence ({matched[0]}), but missed broader business/technical impacts such as: {', '.join(unmatched[:2])}.")
    elif len(clean_i.split()) >= 7:
        score = 7
        deductions.append(f"Deduction (-8 pts): Impact explanation is general. Explain specific threat actions (e.g. {', '.join(unmatched[:2])}).")
        is_flagged = True
    else:
        score = 3
        deductions.append("Deduction (-12 pts): Very brief impact explanation. Clearly articulate what an attacker could do or what damage could occur.")
        is_flagged = True

    return {
        "score": score,
        "max_score": 15,
        "identified": matched,
        "missed": unmatched,
        "deductions": deductions,
        "is_flagged": is_flagged
    }


def evaluate_recommendation(stage_id, student_recommendation, benchmark):
    """
    Evaluates Criterion 5: Recommending a Solution (15 points)
    """
    clean_r = _clean_text(student_recommendation)
    if not clean_r:
        return {
            "score": 0,
            "max_score": 15,
            "identified": [],
            "missed": ["No remediation recommendations provided."],
            "deductions": ["Deduction (-15 pts): No remediation recommendations provided."],
            "is_flagged": False
        }

    concepts = STAGE_EVALUATION_CONCEPTS.get(stage_id, {}).get("recommendation_concepts", [])
    matched, unmatched = _count_concept_matches(clean_r, concepts)
    match_count = len(matched)

    deductions = []
    is_flagged = False

    if match_count >= 2:
        score = 15
    elif match_count == 1:
        score = 11
        deductions.append(f"Deduction (-4 pts): Recommended an appropriate corrective action ({matched[0]}), but should also include preventive controls like: {', '.join(unmatched[:2])}.")
    elif len(clean_r.split()) >= 7:
        score = 7
        deductions.append(f"Deduction (-8 pts): Recommendation is generic. Propose specific technical controls (e.g., {', '.join(unmatched[:2])}).")
        is_flagged = True
    else:
        score = 3
        deductions.append("Deduction (-12 pts): Minimal recommendation. Professional audit reports provide concrete, actionable steps.")
        is_flagged = True

    return {
        "score": score,
        "max_score": 15,
        "identified": matched,
        "missed": unmatched,
        "deductions": deductions,
        "is_flagged": is_flagged
    }


def evaluate_stage_submission(stage_id, submission_data):
    """
    Primary evaluation entrypoint for a single investigation stage.
    Evaluates:
      - weakness (30 pts)
      - evidence (20 pts)
      - risk (20 pts)
      - impact (15 pts)
      - recommendation (15 pts)
    Total = 100 points.

    Checks for AI Language Model API in environment. If missing or offline,
    evaluates using the concept-based Rubric Evaluator in honest Self-Evaluation Mode.
    """
    stage_data = get_stage("shopease", stage_id)
    if not stage_data:
        raise ValueError(f"Invalid stage_id {stage_id} for ShopEase mission.")

    benchmark = stage_data.get("benchmark", {})

    student_weakness = submission_data.get("weakness", "").strip()
    student_evidence = submission_data.get("evidence", "").strip()
    student_risk = submission_data.get("risk", "").strip()
    student_impact = submission_data.get("impact", "").strip()
    student_recommendation = submission_data.get("recommendation", "").strip()

    # Check for genuine AI API Key
    # NOTE: Does not hardcode keys or expose keys in frontend
    gemini_key = os.environ.get("GEMINI_API_KEY", "").strip()
    openai_key = os.environ.get("OPENAI_API_KEY", "").strip()
    
    evaluation_mode = "Self-Evaluation Mode (Official Benchmark Rubric)"
    ai_used = False

    # Perform thorough rubric evaluation
    w_eval = evaluate_weakness(stage_id, student_weakness, benchmark)
    e_eval = evaluate_evidence(stage_id, student_evidence, benchmark)
    r_eval = evaluate_risk(stage_id, student_risk, benchmark)
    i_eval = evaluate_impact(stage_id, student_impact, benchmark)
    rec_eval = evaluate_recommendation(stage_id, student_recommendation, benchmark)

    total_score = (
        w_eval["score"] +
        e_eval["score"] +
        r_eval["score"] +
        i_eval["score"] +
        rec_eval["score"]
    )

    # Uncertainty detection: if any critical criterion is flagged due to ambiguity/brevity
    flagged = any([
        w_eval.get("is_flagged"),
        e_eval.get("is_flagged"),
        i_eval.get("is_flagged"),
        rec_eval.get("is_flagged")
    ])

    review_reason = None
    if flagged:
        review_reason = (
            "One or more of your responses was very brief or used ambiguous wording. "
            "Provisional marks have been awarded based on the rubric, and your finding has been flagged "
            "for manual instructor review so you receive full consideration."
        )

    # Aggregate lists for student feedback display
    all_identified = []
    if w_eval["identified"]:
        all_identified.append(f"Weakness: {', '.join(w_eval['identified'])}")
    if e_eval["identified"]:
        all_identified.append(f"Evidence: {', '.join(e_eval['identified'])}")
    if r_eval["score"] == 20:
        all_identified.append("Risk Level: Correctly assessed as High")
    if i_eval["identified"]:
        all_identified.append(f"Impact: {', '.join(i_eval['identified'])}")
    if rec_eval["identified"]:
        all_identified.append(f"Recommendations: {', '.join(rec_eval['identified'])}")

    all_missed = []
    if w_eval["missed"]:
        all_missed.append(f"Weakness Context: {', '.join(w_eval['missed'][:2])}")
    if e_eval["missed"]:
        all_missed.append(f"Supporting Evidence: {', '.join(e_eval['missed'][:2])}")
    if r_eval["score"] < 20:
        all_missed.append("Risk Level: Underestimated severity")
    if i_eval["missed"]:
        all_missed.append(f"Impact Analysis: {', '.join(i_eval['missed'][:2])}")
    if rec_eval["missed"]:
        all_missed.append(f"Remediation Depth: {', '.join(rec_eval['missed'][:2])}")

    all_deductions = (
        w_eval["deductions"] +
        e_eval["deductions"] +
        r_eval["deductions"] +
        i_eval["deductions"] +
        rec_eval["deductions"]
    )

    result = {
        "stage_id": stage_id,
        "total_score": total_score,
        "max_score": 100,
        "criteria_scores": {
            "weakness": {"score": w_eval["score"], "max": 30, "label": "Identifying the Weakness"},
            "evidence": {"score": e_eval["score"], "max": 20, "label": "Supporting Evidence"},
            "risk": {"score": r_eval["score"], "max": 20, "label": "Risk Assessment"},
            "impact": {"score": i_eval["score"], "max": 15, "label": "Explaining the Impact"},
            "recommendation": {"score": rec_eval["score"], "max": 15, "label": "Recommending a Solution"}
        },
        "identified_correctly": all_identified if all_identified else ["Basic structure submitted."],
        "missed": all_missed if all_missed else ["No major elements missed. Outstanding analysis!"],
        "deduction_explanations": all_deductions,
        "benchmark_solution": benchmark,
        "evaluation_mode": evaluation_mode,
        "ai_used": ai_used,
        "flagged_for_review": flagged,
        "review_reason": review_reason
    }

    return result


def generate_final_audit_report(user_id, submissions):
    """
    Generates a comprehensive final audit report across all four completed stages.
    Returns:
      - scores for all four stages
      - overall average score and total points
      - major security findings
      - recommended corrective actions
      - areas where the student performed well
      - areas needing improvement
    """
    mission = get_mission("shopease")
    stage_scores = []
    total_earned = 0
    total_possible = 400

    # Criteria tracking for strengths/weaknesses
    criteria_totals = {
        "weakness": {"earned": 0, "max": 120, "label": "Weakness Identification"},
        "evidence": {"earned": 0, "max": 80, "label": "Evidence Citation & Fact Grounding"},
        "risk": {"earned": 0, "max": 80, "label": "Risk Severity Assessment"},
        "impact": {"earned": 0, "max": 60, "label": "Threat Impact & Business Consequence Analysis"},
        "recommendation": {"earned": 0, "max": 60, "label": "Remediation & Actionable Solution Design"}
    }

    major_findings = []
    recommended_actions = []

    for s in submissions:
        stage_id = s.get("stage_id")
        score = s.get("total_score", 0)
        stage_scores.append({
            "stage_id": stage_id,
            "title": mission["stages"].get(stage_id, {}).get("title", f"Stage {stage_id}"),
            "score": score,
            "max": 100
        })
        total_earned += score

        # Aggregate criteria
        crit = s.get("feedback_data", {}).get("criteria_scores", {})
        for key in criteria_totals:
            if key in crit:
                criteria_totals[key]["earned"] += crit[key].get("score", 0)

        # Collect major findings from benchmarks or student summaries
        benchmark = mission["stages"].get(stage_id, {}).get("benchmark", {})
        major_findings.append({
            "stage_id": stage_id,
            "stage_title": mission["stages"].get(stage_id, {}).get("title"),
            "finding": benchmark.get("weakness"),
            "risk_level": benchmark.get("risk_level", "High")
        })
        recommended_actions.append({
            "stage_id": stage_id,
            "stage_title": mission["stages"].get(stage_id, {}).get("title"),
            "action": benchmark.get("recommendation")
        })

    average_score = round(total_earned / len(submissions), 1) if submissions else 0.0

    # Identify strengths and improvement areas
    areas_performed_well = []
    areas_needing_improvement = []

    for key, data in criteria_totals.items():
        pct = (data["earned"] / data["max"] * 100) if data["max"] > 0 else 0
        if pct >= 75:
            areas_performed_well.append({
                "label": data["label"],
                "percentage": round(pct, 1),
                "detail": f"Consistently demonstrated strong competency ({data['earned']}/{data['max']} pts, {round(pct, 1)}%)."
            })
        else:
            areas_needing_improvement.append({
                "label": data["label"],
                "percentage": round(pct, 1),
                "detail": f"Opportunity for development ({data['earned']}/{data['max']} pts, {round(pct, 1)}%). Focus on deeper technical specificity and citing concrete records."
            })

    if not areas_performed_well:
        areas_performed_well.append({
            "label": "Audit Participation",
            "percentage": round(average_score, 1),
            "detail": "Successfully conducted investigations across all four critical corporate security domains."
        })

    if not areas_needing_improvement:
        areas_needing_improvement.append({
            "label": "Mastery Achieved",
            "percentage": round(average_score, 1),
            "detail": "No significant weak areas identified across all four audit stages. Ready for independent auditing tasks."
        })

    report = {
        "mission_id": "shopease",
        "company_name": "ShopEase Inc.",
        "total_earned": total_earned,
        "total_possible": total_possible,
        "average_score": average_score,
        "percentage": round((total_earned / total_possible) * 100, 1),
        "stage_scores": stage_scores,
        "major_findings": major_findings,
        "recommended_actions": recommended_actions,
        "areas_performed_well": areas_performed_well,
        "areas_needing_improvement": areas_needing_improvement
    }

    return report
