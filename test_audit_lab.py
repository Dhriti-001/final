"""
test_audit_lab.py
=================
Comprehensive Automated Test Suite for Security Audit Lab
---------------------------------------------------------
Verifies:
1. Scenario & Evidence Completeness across all 4 stages of ShopEase
2. Correct answers written in different wording (semantic evaluation)
3. Partially correct answers and proportional scoring
4. Incorrect answers and detailed deduction explanations
5. Correct findings with weak supporting evidence
6. Good evidence with incorrect / inadequate recommendations
7. Empty submissions handling without crashes
8. Honest Self-Evaluation Mode when API key is missing / unavailable
9. Uncertainty detection and instructor review flagging
10. Risk assessment evaluation (High vs Medium vs Low)
11. Protected routes and unauthenticated redirection
12. Authenticated investigation stage loading (all 4 stages)
13. Student progress and submission persistence in SQLite
14. Multi-stage progression and Final Audit Report generation
15. Mission reset and retake functionality
"""

import os
import unittest
from app import app
from database import init_db, get_db_connection, get_audit_submission, get_or_create_audit_progress, reset_audit_mission
from audit_data import get_mission, get_stage
from audit_evaluator import evaluate_stage_submission, generate_final_audit_report


class SecurityAuditLabTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False

    def setUp(self):
        self.client = app.test_client()
        # Clean user 1 test state for idempotent test runs
        conn = get_db_connection()
        conn.execute("DELETE FROM audit_submissions WHERE user_id = 1")
        conn.execute("DELETE FROM audit_progress WHERE user_id = 1")
        conn.commit()
        conn.close()

    def test_01_all_four_stages_defined_with_teaching_and_evidence(self):
        """Verify all 4 ShopEase stages exist with learning concepts, evidence, and benchmarks."""
        mission = get_mission("shopease")
        self.assertIsNotNone(mission)
        self.assertEqual(mission["id"], "shopease")
        self.assertEqual(mission["total_stages"], 4)

        for s_id in range(1, 5):
            stage = get_stage("shopease", s_id)
            self.assertIsNotNone(stage, f"Stage {s_id} is missing")
            
            # Verify Teaching section
            self.assertIn("learning", stage)
            self.assertIn("topic", stage["learning"])
            self.assertIn("key_concepts", stage["learning"])
            self.assertGreaterEqual(len(stage["learning"]["key_concepts"]), 3)
            for kc in stage["learning"]["key_concepts"]:
                self.assertIn("term", kc)
                self.assertIn("definition", kc)
                self.assertIn("example", kc)

            # Verify Evidence section
            self.assertIn("evidence", stage)
            self.assertIn("document_title", stage["evidence"])

            # Verify Benchmark
            self.assertIn("benchmark", stage)
            self.assertIn("weakness", stage["benchmark"])
            self.assertIn("evidence", stage["benchmark"])
            self.assertEqual(stage["benchmark"]["risk_level"], "High")
            self.assertIn("impact", stage["benchmark"])
            self.assertIn("recommendation", stage["benchmark"])

    def test_02_correct_answers_varied_wording(self):
        """Verify that technically correct answers in different phrasing receive high/full credit."""
        # Stage 1: David Chen ex-employee admin account
        # Phrasing 1: Uses terms 'former employee', 'AWS root', 'resigned'
        sub1 = {
            "weakness": "A former employee who resigned months ago still has an active account with AWS root and domain admin privileges.",
            "evidence": "David Chen resigned on October 14 as recorded in HR ticket 8821, but in the access register his account is still marked active with a remote login yesterday.",
            "risk": "High",
            "impact": "An attacker compromising these credentials has full administrative control over the company cloud infrastructure and can steal customer PII or plant ransomware.",
            "recommendation": "Immediately disable David Chen's account, revoke all API keys, conduct an audit of recent logins, and implement automated offboarding."
        }
        res1 = evaluate_stage_submission(1, sub1)
        self.assertGreaterEqual(res1["total_score"], 90, f"Expected >= 90 but got {res1['total_score']}")
        self.assertGreaterEqual(res1["criteria_scores"]["weakness"]["score"], 25)
        self.assertGreaterEqual(res1["criteria_scores"]["evidence"]["score"], 18)
        self.assertEqual(res1["criteria_scores"]["risk"]["score"], 20)

        # Phrasing 2: Uses terms 'departed staff', 'sysadmin', 'offboarding failure', 'ex-employee'
        sub2 = {
            "weakness": "The offboarding process failed because a departed DevOps worker's elevated administrator account remains enabled.",
            "evidence": "HR departure ticket 8821 states David Chen left in October, yet his user status is active with domain admin rights and logged in from 198.51.100.44 violating POL-SEC-04.",
            "risk": "High",
            "impact": "Unauthorized access allowing complete takeover of corporate servers, data breach of customer records, and database deletion.",
            "recommendation": "Deactivate the user account right away, review all session logs since departure, and enforce regular user access reviews."
        }
        res2 = evaluate_stage_submission(1, sub2)
        self.assertGreaterEqual(res2["total_score"], 90)

    def test_03_partially_correct_answers(self):
        """Verify partially correct answers receive proportional partial credit with clear deductions."""
        # Mentions David Chen has an account, but misses that he resigned or has admin rights
        partial_sub = {
            "weakness": "David Chen has an active account in the system.",
            "evidence": "I see David Chen in the user register.",
            "risk": "Medium", # Underestimated risk
            "impact": "He could log into the system.",
            "recommendation": "Check his account."
        }
        res = evaluate_stage_submission(1, partial_sub)
        self.assertLess(res["total_score"], 70)
        self.assertGreater(res["total_score"], 20)
        # Verify deduction explanations are generated
        self.assertGreater(len(res["deduction_explanations"]), 0)
        # Check risk deduction
        self.assertEqual(res["criteria_scores"]["risk"]["score"], 10)

    def test_04_incorrect_answers(self):
        """Verify off-topic / incorrect answers receive low scores with clear deduction explanations."""
        bad_sub = {
            "weakness": "The office printer is out of paper and colors look faded.",
            "evidence": "Looking at the print queue.",
            "risk": "Low",
            "impact": "Employees cannot print physical memos.",
            "recommendation": "Buy more toner cartridges."
        }
        res = evaluate_stage_submission(1, bad_sub)
        self.assertLess(res["total_score"], 35)
        self.assertGreaterEqual(len(res["deduction_explanations"]), 3)
        self.assertEqual(res["criteria_scores"]["risk"]["score"], 0)

    def test_05_correct_findings_with_weak_supporting_evidence(self):
        """Verify that identifying the weakness correctly while citing weak evidence scores appropriately."""
        sub = {
            "weakness": "An administrator account belonging to a former employee who resigned months ago is still active with domain admin privileges.",
            "evidence": "I noticed it in the table.", # Very weak evidence
            "risk": "High",
            "impact": "Full compromise of the AWS cloud environment, ransomware infection, or customer data exfiltration.",
            "recommendation": "Immediately disable the account and audit all historical sessions."
        }
        res = evaluate_stage_submission(1, sub)
        # Weakness should get full / high marks (25-30)
        self.assertGreaterEqual(res["criteria_scores"]["weakness"]["score"], 25)
        # Evidence should get low / penalized marks (<= 10)
        self.assertLessEqual(res["criteria_scores"]["evidence"]["score"], 10)
        # Explanation of deduction must mention evidence
        evidence_deductions = [d for d in res["deduction_explanations"] if "evidence" in d.lower()]
        self.assertGreater(len(evidence_deductions), 0)

    def test_06_good_evidence_with_incorrect_recommendations(self):
        """Verify that good evidence with an unrelated or inadequate recommendation scores each criterion separately."""
        sub = {
            "weakness": "Former employee account remains active with Domain Admin rights.",
            "evidence": "HR Ticket #8821 shows David Chen resigned on October 14, 2025, but the register lists him as ACTIVE with Domain Admin and AWS Root, logging in yesterday from IP 198.51.100.44.",
            "risk": "High",
            "impact": "Complete unauthorized access to cloud assets and potential theft of customer PII.",
            "recommendation": "Give him a bonus and tell him to be careful." # Inadequate/bad solution
        }
        res = evaluate_stage_submission(1, sub)
        # Evidence gets high marks (>= 18)
        self.assertGreaterEqual(res["criteria_scores"]["evidence"]["score"], 18)
        # Recommendation gets low marks (<= 7)
        self.assertLessEqual(res["criteria_scores"]["recommendation"]["score"], 7)

    def test_07_empty_submissions(self):
        """Verify empty submissions evaluate gracefully to 0 points without errors."""
        empty_sub = {
            "weakness": "",
            "evidence": "",
            "risk": "",
            "impact": "",
            "recommendation": ""
        }
        res = evaluate_stage_submission(1, empty_sub)
        self.assertEqual(res["total_score"], 0)
        self.assertEqual(res["criteria_scores"]["weakness"]["score"], 0)
        self.assertEqual(res["criteria_scores"]["evidence"]["score"], 0)
        self.assertEqual(res["criteria_scores"]["risk"]["score"], 0)
        self.assertEqual(res["criteria_scores"]["impact"]["score"], 0)
        self.assertEqual(res["criteria_scores"]["recommendation"]["score"], 0)
        self.assertGreaterEqual(len(res["deduction_explanations"]), 4)

    def test_08_api_key_missing_honest_self_evaluation(self):
        """Verify that when no AI API key is set, the system honestly labels Self-Evaluation Mode."""
        # Ensure environment keys are not simulated
        orig_gemini = os.environ.get("GEMINI_API_KEY")
        if "GEMINI_API_KEY" in os.environ:
            del os.environ["GEMINI_API_KEY"]

        sub = {
            "weakness": "No MFA enforced and passwords only.",
            "evidence": "auth.enforce_mfa is DISABLED and 14,000 login attempts occurred.",
            "risk": "High",
            "impact": "Brute force credential compromise.",
            "recommendation": "Enforce MFA and account lockout."
        }
        res = evaluate_stage_submission(2, sub)
        self.assertIn("Self-Evaluation Mode", res["evaluation_mode"])
        self.assertFalse(res["ai_used"])

        # Restore
        if orig_gemini:
            os.environ["GEMINI_API_KEY"] = orig_gemini

    def test_09_uncertainty_flagging_for_review(self):
        """Verify very brief or ambiguous answers trigger flagged_for_review = True."""
        brief_sub = {
            "weakness": "Account issue.", # Only 2 words
            "evidence": "Some document.", # Very brief
            "risk": "High",
            "impact": "Bad stuff.",
            "recommendation": "Fix it."
        }
        res = evaluate_stage_submission(1, brief_sub)
        self.assertTrue(res["flagged_for_review"])
        self.assertIsNotNone(res["review_reason"])
        self.assertIn("instructor review", res["review_reason"].lower())

    def test_10_risk_assessment_scoring(self):
        """Verify High risk awards 20 pts, Medium awards 10 pts, and Low awards 0 pts."""
        benchmark = {"risk_level": "High"}
        from audit_evaluator import evaluate_risk
        
        r_high = evaluate_risk(1, "High", benchmark)
        self.assertEqual(r_high["score"], 20)
        self.assertEqual(len(r_high["deductions"]), 0)

        r_med = evaluate_risk(1, "Medium", benchmark)
        self.assertEqual(r_med["score"], 10)
        self.assertEqual(len(r_med["deductions"]), 1)
        self.assertIn("-10 pts", r_med["deductions"][0])

        r_low = evaluate_risk(1, "Low", benchmark)
        self.assertEqual(r_low["score"], 0)
        self.assertEqual(len(r_low["deductions"]), 1)
        self.assertIn("-20 pts", r_low["deductions"][0])

    def test_11_routes_unauthenticated_redirect(self):
        """Verify unauthenticated requests redirect to /login."""
        routes = [
            "/audit-lab",
            "/audit-lab/mission/shopease/stage/1",
            "/audit-lab/mission/shopease/report"
        ]
        for route in routes:
            resp = self.client.get(route, follow_redirects=False)
            self.assertEqual(resp.status_code, 302)
            self.assertIn("/login", resp.headers["Location"])

    def test_12_authenticated_stage_rendering(self):
        """Verify all 4 investigation stages render with learning, evidence, and answer forms."""
        with self.client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "cadet"

        for s_id in range(1, 5):
            resp = self.client.get(f"/audit-lab/mission/shopease/stage/{s_id}")
            self.assertEqual(resp.status_code, 200)
            self.assertIn(b"Security Audit Lab", resp.data)
            self.assertIn(b"ShopEase", resp.data)
            self.assertIn(b"Step 1 &bull; Learn Concepts First", resp.data)
            self.assertIn(b"Step 2 &bull; Inspect Company Evidence", resp.data)
            self.assertIn(b"Step 3 &bull; Submit Your Audit Finding", resp.data)
            self.assertIn(b"1. What security weakness did you identify?", resp.data)
            self.assertIn(b"2. What evidence supports your finding?", resp.data)
            self.assertIn(b"3. How serious is the risk?", resp.data)
            self.assertIn(b"4. What could happen because of this weakness?", resp.data)
            self.assertIn(b"5. What would you recommend to fix it?", resp.data)

    def test_13_submission_saving_and_retrieval(self):
        """Verify submitting findings saves to database and reflects in the stage view."""
        with self.client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "cadet"

        # Submit Stage 1 finding
        resp = self.client.post("/audit-lab/mission/shopease/stage/1/submit", data={
            "weakness": "Former employee David Chen has an active account with Domain Admin privileges.",
            "evidence": "HR ticket 8821 states resignation Oct 14, but user register lists account active with AWS root and login yesterday.",
            "risk": "High",
            "impact": "Complete administrative takeover and customer database theft.",
            "recommendation": "Immediately disable account and review all recent session logs."
        }, follow_redirects=True)

        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Audit Evaluation Results", resp.data)
        self.assertIn(b"/ 100 PTS", resp.data)
        self.assertIn(b"Recommended Professional Solution", resp.data)

        # Verify database record
        sub = get_audit_submission(1, "shopease", 1)
        self.assertIsNotNone(sub)
        self.assertEqual(sub["stage_id"], 1)
        self.assertGreater(sub["total_score"], 70)
        self.assertIn("criteria_scores", sub["feedback_data"])

        # Verify progress tracking
        progress = get_or_create_audit_progress(1, "shopease")
        self.assertEqual(progress["completed_stages"], 1)
        self.assertEqual(progress["current_stage"], 2)

    def test_14_progression_across_all_four_stages_and_final_report(self):
        """Verify completing all four stages generates the comprehensive Final Audit Report."""
        with self.client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "cadet"

        sample_submissions = [
            # Stage 1
            {
                "weakness": "Resigned employee David Chen still active with domain admin and cloud root rights.",
                "evidence": "HR ticket 8821 says David resigned Oct 14 2025, but register shows active status and external login yesterday violating POL-SEC-04.",
                "risk": "High",
                "impact": "Attacker can gain full administrative control, steal customer records, or deploy ransomware.",
                "recommendation": "Immediately disable account, revoke AWS keys, and implement automated HR offboarding."
            },
            # Stage 2
            {
                "weakness": "Passwords-only authentication with no MFA, no account lockout, and no alerts.",
                "evidence": "Configuration shows auth.enforce_mfa DISABLED, lockout threshold 0, and log shows 14,280 failed attempts from 203.0.113.88 against admin.",
                "risk": "High",
                "impact": "Brute force and credential stuffing attacks can easily compromise administrator accounts.",
                "recommendation": "Enforce MFA for all users, implement a 5-attempt lockout policy, and configure anomaly alerts."
            },
            # Stage 3
            {
                "weakness": "Backups are manual and infrequent, stored on local NAS without offsite copy, and never tested.",
                "evidence": "Backup spec shows manual dumps every 3 to 6 months, storage on local NAS share with no cloud copy, never tested, and Black Friday incident lost 3 weeks of orders.",
                "risk": "High",
                "impact": "Ransomware could encrypt both servers and backups simultaneously causing permanent data loss.",
                "recommendation": "Adopt 3-2-1 backup strategy with automated daily backups, offsite immutable cloud vault, and quarterly restoration testing."
            },
            # Stage 4
            {
                "weakness": "No centralized patch management or update schedule, leaving critical CVEs unpatched.",
                "evidence": "Policy POL-IT-09 has no WSUS or MDM. Web server has critical CVE-2021-42013 pending 11 months, db server missing patches, and 74% of employees snooze updates.",
                "risk": "High",
                "impact": "Remote code execution on public web server leading to database compromise and network-wide malware.",
                "recommendation": "Deploy centralized patch management like Intune or WSUS, enforce 14-day patching SLA, and mandate automated reboots."
            }
        ]

        # Submit all 4 stages
        for s_id, s_data in enumerate(sample_submissions, 1):
            resp = self.client.post(f"/audit-lab/mission/shopease/stage/{s_id}/submit", data=s_data, follow_redirects=True)
            self.assertEqual(resp.status_code, 200)

        # View Final Audit Report
        report_resp = self.client.get("/audit-lab/mission/shopease/report")
        self.assertEqual(report_resp.status_code, 200)
        self.assertIn(b"ShopEase Inc. - Cybersecurity Posture Assessment", report_resp.data)
        self.assertIn(b"Stage-by-Stage Performance Scorecard", report_resp.data)
        self.assertIn(b"Consolidated Major Security Findings", report_resp.data)
        self.assertIn(b"Recommended Corrective Action Plan", report_resp.data)
        self.assertIn(b"Areas Where You Performed Well", report_resp.data)
        self.assertIn(b"Areas That Need Improvement", report_resp.data)

        # Verify progress is marked completed
        progress = get_or_create_audit_progress(1, "shopease")
        self.assertEqual(progress["is_completed"], 1)
        self.assertEqual(progress["completed_stages"], 4)
        self.assertGreater(progress["average_score"], 80.0)

    def test_15_reset_mission(self):
        """Verify resetting a mission clears submissions and resets progress."""
        with self.client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "cadet"

        # Submit stage 1
        self.client.post("/audit-lab/mission/shopease/stage/1/submit", data={
            "weakness": "Active admin account for David Chen.",
            "evidence": "HR ticket 8821.",
            "risk": "High",
            "impact": "Account takeover.",
            "recommendation": "Disable account."
        })

        # Reset
        reset_resp = self.client.post("/audit-lab/mission/shopease/reset", follow_redirects=True)
        self.assertEqual(reset_resp.status_code, 200)

        # Check DB
        sub = get_audit_submission(1, "shopease", 1)
        self.assertIsNone(sub)
        progress = get_or_create_audit_progress(1, "shopease")
        self.assertEqual(progress["completed_stages"], 0)
        self.assertEqual(progress["is_completed"], 0)


if __name__ == "__main__":
    unittest.main()
