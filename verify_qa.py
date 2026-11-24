"""
verify_qa.py
============
Comprehensive Technical Quality Assurance & Verification Script
---------------------------------------------------------------
Executes automated QA tests covering:
1. Substantially different but technically equivalent answers (Fair Scoring)
2. Partial credit evaluation & Misconception non-rewarding
3. End-to-end browser simulation across all 4 investigation stages
4. Session persistence across logout, login, and page refresh
5. Cross-user isolation: User A cannot see or modify User B's audit data
6. Safe user-scoped mission reset: User A's reset leaves User B untouched
"""

import sys
import unittest
from app import app
from database import (
    init_db, get_db_connection,
    get_audit_submission, get_user_audit_submissions,
    get_or_create_audit_progress, reset_audit_mission
)
from audit_evaluator import evaluate_stage_submission, evaluate_weakness, evaluate_evidence, evaluate_risk


class QualityAssuranceVerification(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False

    def setUp(self):
        self.client = app.test_client()
        conn = get_db_connection()
        # Clean test users 1 and 2 audit data
        conn.execute("DELETE FROM audit_submissions WHERE user_id IN (1, 2)")
        conn.execute("DELETE FROM audit_progress WHERE user_id IN (1, 2)")
        conn.commit()
        conn.close()

    def test_qa_01_technically_equivalent_varied_answers(self):
        """
        QA Point 3: Test substantially different but technically equivalent student answers
        across all 4 stages to ensure fair scoring.
        """
        # --- Stage 1 Equivalent Variants ---
        s1_academic = {
            "weakness": "Failure in identity lifecycle deprovisioning resulting in active administrative cloud and domain credentials for a terminated engineer.",
            "evidence": "Access register reflects status ACTIVE with AWS root and Domain Admin for David Chen despite HR departure ticket 8821 recording his exit on October 14.",
            "risk": "High",
            "impact": "Unrestricted administrative takeover enabling exfiltration of customer PII and database deletion.",
            "recommendation": "Immediately revoke all active credentials and sessions, implement automated HR-IT offboarding synchronization, and schedule periodic user access audits."
        }
        res_s1_academic = evaluate_stage_submission(1, s1_academic)
        self.assertGreaterEqual(res_s1_academic["total_score"], 90)

        s1_casual = {
            "weakness": "An old sysadmin who quit 4 months ago still has his root admin user account turned on.",
            "evidence": "David Chen quit in October according to ticket 8821 but he is still active in the list and logged in yesterday from an IP address.",
            "risk": "High",
            "impact": "A hacker could steal his password and do whatever they want to the servers or steal customer records.",
            "recommendation": "Disable his user right away, check all the logs to see what he did, and make sure HR tells IT automatically."
        }
        res_s1_casual = evaluate_stage_submission(1, s1_casual)
        self.assertGreaterEqual(res_s1_casual["total_score"], 90)

        # --- Stage 2 Equivalent Variants ---
        s2_standard = {
            "weakness": "Single-factor password dependency with no multi-factor authentication, no account lockout threshold, and missing login alerts.",
            "evidence": "Configuration parameters show auth.enforce_mfa DISABLED, lockout threshold 0, and log shows 14,280 failed attempts from 203.0.113.88 against admin.",
            "risk": "High",
            "impact": "Adversaries can execute automated brute-force attacks leading to administrative account takeover and customer data breaches.",
            "recommendation": "Mandate MFA on all accounts, configure an account lockout policy after 5 attempts, and enable suspicious login alerts."
        }
        res_s2 = evaluate_stage_submission(2, s2_standard)
        self.assertGreaterEqual(res_s2["total_score"], 85)

        # --- Stage 3 Equivalent Variants ---
        s3_academic = {
            "weakness": "Violation of the 3-2-1 backup principle: manual ad-hoc backups stored exclusively on the same local subnet without immutable offsite storage and no restoration testing.",
            "evidence": "Database specification confirms manual pg_dump every 3 to 6 months, storage on \\\\shopease-nas01 with no cloud copy, never tested restoration, and incident INC-2025-11-28 caused 3 weeks of lost orders.",
            "risk": "High",
            "impact": "Ransomware could encrypt the primary database and local NAS backups simultaneously, or disk corruption causes irreversible data loss.",
            "recommendation": "Enforce the 3-2-1 rule with automated daily incremental backups, offsite immutable cloud vaulting, and quarterly restoration testing drills."
        }
        res_s3 = evaluate_stage_submission(3, s3_academic)
        self.assertGreaterEqual(res_s3["total_score"], 90)

        # --- Stage 4 Equivalent Variants ---
        s4_formal = {
            "weakness": "Lack of centralized patch management and update governance, resulting in critical unpatched remote code execution vulnerabilities on production servers and neglected employee workstations.",
            "evidence": "Policy POL-IT-09 shows no MDM or WSUS. Asset report shows web server with CVE-2021-42013 pending 11 months, database server missing security patches for 8 months, and 74% of employees snoozing updates.",
            "risk": "High",
            "impact": "External actors can exploit CVE-2021-42013 to achieve remote code execution on the web server, pivot to internal customer databases, and compromise workstations.",
            "recommendation": "Deploy centralized patch management (WSUS/Intune), establish a strict 14-day patching SLA for critical CVEs, and mandate automated reboots."
        }
        res_s4 = evaluate_stage_submission(4, s4_formal)
        self.assertGreaterEqual(res_s4["total_score"], 90)

    def test_qa_02_partial_credit_and_misconception_penalty(self):
        """
        QA Point 4: Verify that partially correct answers receive appropriate partial credit
        and that technical misconceptions are NOT rewarded.
        """
        # Misconception 1: Blaming the wrong user/department (Sarah Jenkins / Marketing)
        misconception_sub = {
            "weakness": "Sarah Jenkins has marketing access and her marketing campaigns might have typos.",
            "evidence": "The register lists Sarah Jenkins as Marketing Director.",
            "risk": "Low", # Severe underestimation
            "impact": "Customers might read a promotional email with bad grammar.",
            "recommendation": "Hire an English proofreader for marketing."
        }
        res_misc = evaluate_stage_submission(1, misconception_sub)
        self.assertLess(res_misc["total_score"], 30)
        self.assertEqual(res_misc["criteria_scores"]["risk"]["score"], 0)
        self.assertTrue(any("misconception" in d.lower() or "underestimated" in d.lower() for d in res_misc["deduction_explanations"]))

        # Misconception 2: Blaming the database size instead of backup frequency and lack of offsite storage
        db_size_sub = {
            "weakness": "The database is too big (420 GB).",
            "evidence": "It says 420 GB in the table.",
            "risk": "Low",
            "impact": "Hard drive runs out of space.",
            "recommendation": "Delete older customers."
        }
        res_size = evaluate_stage_submission(3, db_size_sub)
        self.assertLess(res_size["total_score"], 35)

        # Valid Partial Credit: Student identifies ex-employee issue but omits evidence and gives generic impact
        partial_sub = {
            "weakness": "An ex-employee who resigned still has an active admin account.", # Good identification (25-30)
            "evidence": "I read the document.", # Very weak evidence (<= 10)
            "risk": "High", # Correct risk (20)
            "impact": "Something bad might happen.", # Vague impact (<= 7)
            "recommendation": "Lock the account." # Brief recommendation (<= 11)
        }
        res_partial = evaluate_stage_submission(1, partial_sub)
        self.assertGreater(res_partial["total_score"], 50)
        self.assertLess(res_partial["total_score"], 78)
        self.assertGreaterEqual(res_partial["criteria_scores"]["weakness"]["score"], 25)
        self.assertLessEqual(res_partial["criteria_scores"]["evidence"]["score"], 10)

    def test_qa_03_end_to_end_investigation_simulation(self):
        """
        QA Point 5: Confirm that the four investigation stages work from beginning to end
        simulating actual user navigation, submission, feedback display, and final report.
        """
        # 1. Login
        login_resp = self.client.post("/login", data={
            "action": "login",
            "username": "cadet",
            "password": "password123"
        }, follow_redirects=True)
        self.assertEqual(login_resp.status_code, 200)

        # 2. Access /audit-lab -> redirects to Stage 1
        entry_resp = self.client.get("/audit-lab", follow_redirects=True)
        self.assertEqual(entry_resp.status_code, 200)
        self.assertIn(b"Stage 1", entry_resp.data)
        self.assertIn(b"Access Register", entry_resp.data)

        # 3. Submit Stage 1
        s1_resp = self.client.post("/audit-lab/mission/shopease/stage/1/submit", data={
            "weakness": "Resigned employee David Chen has an active Domain Admin account.",
            "evidence": "HR ticket 8821 states resignation Oct 14, but register shows active status with AWS Root and login yesterday.",
            "risk": "High",
            "impact": "Complete unauthorized cloud takeover and customer PII theft.",
            "recommendation": "Immediately deactivate account and review all recent session logs."
        }, follow_redirects=True)
        self.assertEqual(s1_resp.status_code, 200)
        self.assertIn(b"Audit Evaluation Results", s1_resp.data)
        self.assertIn(b"Recommended Professional Solution", s1_resp.data)

        # 4. Advance to Stage 2 & Submit
        s2_page = self.client.get("/audit-lab/mission/shopease/stage/2")
        self.assertEqual(s2_page.status_code, 200)
        self.assertIn(b"Login Security", s2_page.data)

        s2_resp = self.client.post("/audit-lab/mission/shopease/stage/2/submit", data={
            "weakness": "No MFA enforced, no account lockout threshold, and no login alerts.",
            "evidence": "Config shows auth.enforce_mfa false, lockout threshold 0, and 14,280 failed attempts in the gateway log.",
            "risk": "High",
            "impact": "Automated brute force attacks can crack administrator passwords and steal customer orders.",
            "recommendation": "Enforce MFA for all staff, configure lockout after 5 attempts, and deploy rate limiting."
        }, follow_redirects=True)
        self.assertEqual(s2_resp.status_code, 200)

        # 5. Advance to Stage 3 & Submit
        s3_resp = self.client.post("/audit-lab/mission/shopease/stage/3/submit", data={
            "weakness": "Backups are manual and infrequent, stored on local NAS without offsite copy, and never tested.",
            "evidence": "Backup spec shows manual dumps every 3 to 6 months, storage on \\\\shopease-nas01, never tested restoration, and Black Friday incident lost 3 weeks of data.",
            "risk": "High",
            "impact": "Ransomware could encrypt the NAS and production database simultaneously causing permanent loss.",
            "recommendation": "Adopt 3-2-1 backup strategy with automated daily backups, offsite immutable cloud vault, and quarterly restoration drills."
        }, follow_redirects=True)
        self.assertEqual(s3_resp.status_code, 200)

        # 6. Advance to Stage 4 & Submit
        s4_resp = self.client.post("/audit-lab/mission/shopease/stage/4/submit", data={
            "weakness": "No centralized patch management or update schedule, leaving critical CVEs unpatched.",
            "evidence": "Policy POL-IT-09 has no WSUS or MDM. Web server has critical CVE-2021-42013 pending 11 months, db server missing patches, and 74% of employees snooze updates.",
            "risk": "High",
            "impact": "Remote code execution on public web server leading to database compromise and network-wide malware.",
            "recommendation": "Deploy centralized patch management like Intune or WSUS, enforce 14-day patching SLA, and mandate automated reboots."
        }, follow_redirects=True)
        self.assertEqual(s4_resp.status_code, 200)

        # 7. Load Final Report
        report_resp = self.client.get("/audit-lab/mission/shopease/report")
        self.assertEqual(report_resp.status_code, 200)
        self.assertIn(b"ShopEase Inc. - Cybersecurity Posture Assessment", report_resp.data)
        self.assertIn(b"Stage-by-Stage Performance Scorecard", report_resp.data)
        self.assertIn(b"Consolidated Major Security Findings", report_resp.data)
        self.assertIn(b"Recommended Corrective Action Plan", report_resp.data)

    def test_qa_04_session_persistence_across_logout_and_refresh(self):
        """
        QA Point 6: Verify student submissions and progress remain saved after logging out,
        logging back in and refreshing the browser.
        """
        # Step 1: Login as cadet
        self.client.post("/login", data={"action": "login", "username": "cadet", "password": "password123"})
        
        # Step 2: Submit Stage 1 finding
        self.client.post("/audit-lab/mission/shopease/stage/1/submit", data={
            "weakness": "Ex-employee David Chen account active with Domain Admin privileges.",
            "evidence": "HR ticket 8821 resignation Oct 14, active status in user register with login yesterday.",
            "risk": "High",
            "impact": "Full cloud compromise and customer record theft.",
            "recommendation": "Immediately disable account and review all recent sessions."
        })

        # Step 3: Refresh stage 1 page
        refresh_resp = self.client.get("/audit-lab/mission/shopease/stage/1")
        self.assertEqual(refresh_resp.status_code, 200)
        self.assertIn(b"Ex-employee David Chen account active", refresh_resp.data)
        self.assertIn(b"Audit Evaluation Results", refresh_resp.data)

        # Step 4: Logout
        logout_resp = self.client.get("/logout", follow_redirects=True)
        self.assertEqual(logout_resp.status_code, 200)

        # Step 5: Verify unauthenticated request does not leak data
        anon_resp = self.client.get("/audit-lab/mission/shopease/stage/1", follow_redirects=False)
        self.assertEqual(anon_resp.status_code, 302)

        # Step 6: Log back in as cadet
        relogin_resp = self.client.post("/login", data={"action": "login", "username": "cadet", "password": "password123"}, follow_redirects=True)
        self.assertEqual(relogin_resp.status_code, 200)

        # Step 7: Verify Stage 1 submission and evaluation are intact
        recheck_resp = self.client.get("/audit-lab/mission/shopease/stage/1")
        self.assertEqual(recheck_resp.status_code, 200)
        self.assertIn(b"Ex-employee David Chen account active", recheck_resp.data)
        self.assertIn(b"Audit Evaluation Results", recheck_resp.data)

    def test_qa_05_cross_user_isolation(self):
        """
        QA Point 7: Confirm that different student accounts cannot access each other's submissions
        or audit reports.
        """
        # User 1 (cadet) submits findings
        with self.client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "cadet"

        self.client.post("/audit-lab/mission/shopease/stage/1/submit", data={
            "weakness": "Cadet Weakness Finding #1",
            "evidence": "Cadet Evidence Details #1",
            "risk": "High",
            "impact": "Cadet Impact #1",
            "recommendation": "Cadet Recommendation #1"
        })

        # Switch session to User 2 (sarah_infosec)
        with self.client.session_transaction() as sess:
            sess["user_id"] = 2
            sess["username"] = "sarah_infosec"

        # User 2 checks Stage 1 - must NOT see Cadet's submission
        u2_resp = self.client.get("/audit-lab/mission/shopease/stage/1")
        self.assertEqual(u2_resp.status_code, 200)
        self.assertNotIn(b"Cadet Weakness Finding #1", u2_resp.data)
        self.assertNotIn(b"Cadet Evidence Details #1", u2_resp.data)
        # Should not have evaluation results card
        self.assertNotIn(b"Audit Evaluation Results", u2_resp.data)

        # User 2 submits their own finding
        self.client.post("/audit-lab/mission/shopease/stage/1/submit", data={
            "weakness": "Sarah Security Analysis finding",
            "evidence": "Sarah Evidence Citation",
            "risk": "High",
            "impact": "Sarah Impact Explanation",
            "recommendation": "Sarah Remediation Strategy"
        })

        # Verify User 1's submission in database is completely separate from User 2's
        sub_u1 = get_audit_submission(1, "shopease", 1)
        sub_u2 = get_audit_submission(2, "shopease", 1)
        self.assertIsNotNone(sub_u1)
        self.assertIsNotNone(sub_u2)
        self.assertEqual(sub_u1["weakness_answer"], "Cadet Weakness Finding #1")
        self.assertEqual(sub_u2["weakness_answer"], "Sarah Security Analysis finding")

    def test_qa_06_mission_reset_cross_user_safety(self):
        """
        QA Point 9: Confirm that mission reset operations cannot accidentally erase other students' records.
        """
        # Setup: Both User 1 and User 2 have submissions
        with self.client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "cadet"
        self.client.post("/audit-lab/mission/shopease/stage/1/submit", data={
            "weakness": "Cadet Finding",
            "evidence": "HR ticket 8821",
            "risk": "High",
            "impact": "Admin takeover",
            "recommendation": "Revoke account"
        })

        with self.client.session_transaction() as sess:
            sess["user_id"] = 2
            sess["username"] = "sarah_infosec"
        self.client.post("/audit-lab/mission/shopease/stage/1/submit", data={
            "weakness": "Sarah Finding",
            "evidence": "HR ticket 8821",
            "risk": "High",
            "impact": "Admin takeover",
            "recommendation": "Revoke account"
        })

        # User 1 resets mission
        with self.client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "cadet"
        reset_resp = self.client.post("/audit-lab/mission/shopease/reset", follow_redirects=True)
        self.assertEqual(reset_resp.status_code, 200)

        # User 1 submissions are cleared
        self.assertIsNone(get_audit_submission(1, "shopease", 1))
        prog_u1 = get_or_create_audit_progress(1, "shopease")
        self.assertEqual(prog_u1["completed_stages"], 0)

        # User 2 submissions MUST remain completely intact!
        sub_u2 = get_audit_submission(2, "shopease", 1)
        self.assertIsNotNone(sub_u2)
        self.assertEqual(sub_u2["weakness_answer"], "Sarah Finding")
        prog_u2 = get_or_create_audit_progress(2, "shopease")
        self.assertEqual(prog_u2["completed_stages"], 1)


if __name__ == "__main__":
    unittest.main()
