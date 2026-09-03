"""LOT 6B corrective-action regression tests."""

import unittest
from datetime import datetime, timedelta

from fastapi.testclient import TestClient

from app.models import CorrectiveAction, CorrectiveActionHistory
from app.services.corrective_action_service import (
    BLOCKED, CLOSED, IN_PROGRESS, OPEN, CorrectiveActionError,
    corrective_action_dashboard, create_corrective_action, update_corrective_action,
)
from app.services.quality_review_service import REVIEW_NON_COMPLIANT, REVIEW_PENDING, create_quality_review
import test_lot_6a


class Lot6BCorrectiveActionTests(unittest.TestCase):
    def setUp(self):
        self.base = test_lot_6a.Lot6AQualityReviewTests()
        self.base.setUp()
        self.db = self.base.db
        self.now = self.base.now
        self.review = create_quality_review(
            self.db, decision_id=self.base.fp.id, review_status=REVIEW_NON_COMPLIANT,
            quality_comment="Écart qualité.", actor=self.base.actor(self.base.auditor),
        )
        self.db.commit()

    def tearDown(self):
        self.base.tearDown()

    def test_01_create_from_eligible_review_and_kpis(self):
        action = create_corrective_action(
            self.db, quality_review_id=self.review.id, responsible_user_id=self.base.analyst1.id,
            due_date=(self.now - timedelta(days=1)).date(), priority="HAUTE",
            comment="Plan d'action.", actor=self.base.actor(self.base.admin),
        )
        self.db.commit()
        report = corrective_action_dashboard(self.db, now=self.now)
        self.assertEqual(action.status, OPEN)
        self.assertEqual(report["kpis"], {"open": 1, "overdue": 1, "closed": 0})
        self.assertEqual(len(action.history), 1)

    def test_02_rejects_compliant_review_and_invalid_responsible(self):
        compliant = create_quality_review(
            self.db, decision_id=self.base.confirmed.id, review_status="CONFORME",
            quality_comment=None, actor=self.base.actor(self.base.auditor),
        )
        with self.assertRaises(CorrectiveActionError):
            create_corrective_action(
                self.db, quality_review_id=compliant.id, responsible_user_id=self.base.analyst1.id,
                due_date=self.now.date(), priority="MOYENNE", comment=None,
                actor=self.base.actor(self.base.admin),
            )
        with self.assertRaises(CorrectiveActionError):
            create_corrective_action(
                self.db, quality_review_id=self.review.id, responsible_user_id=self.base.supervisor.id,
                due_date=self.now.date(), priority="MOYENNE", comment=None,
                actor=self.base.actor(self.base.admin),
            )

    def test_03_assigned_analyst_updates_but_cannot_reassign_or_close_twice(self):
        action = create_corrective_action(
            self.db, quality_review_id=self.review.id, responsible_user_id=self.base.analyst1.id,
            due_date=self.now.date(), priority="MOYENNE", comment=None,
            actor=self.base.actor(self.base.supervisor),
        )
        self.db.commit()
        updated = update_corrective_action(
            self.db, action_id=action.id, status=IN_PROGRESS, comment="Traitement commencé.",
            actor=self.base.actor(self.base.analyst1),
        )
        self.assertEqual(updated.status, IN_PROGRESS)
        with self.assertRaises(PermissionError):
            update_corrective_action(
                self.db, action_id=action.id, status=BLOCKED, comment=None,
                responsible_user_id=self.base.analyst2.id, actor=self.base.actor(self.base.analyst1),
            )
        closed = update_corrective_action(
            self.db, action_id=action.id, status=CLOSED, comment="Terminé.",
            actor=self.base.actor(self.base.supervisor),
        )
        self.assertIsNotNone(closed.closed_at)
        with self.assertRaises(CorrectiveActionError):
            update_corrective_action(
                self.db, action_id=action.id, status=IN_PROGRESS, comment=None,
                actor=self.base.actor(self.base.supervisor),
            )

    def test_04_history_is_append_only(self):
        action = create_corrective_action(
            self.db, quality_review_id=self.review.id, responsible_user_id=self.base.analyst1.id,
            due_date=self.now.date(), priority="BASSE", comment=None, actor=self.base.actor(self.base.admin),
        )
        self.db.commit()
        history = self.db.query(CorrectiveActionHistory).filter_by(corrective_action_id=action.id).one()
        history.new_status = CLOSED
        with self.assertRaises(ValueError):
            self.db.flush()
        self.db.rollback()
        history = self.db.query(CorrectiveActionHistory).filter_by(id=history.id).one()
        self.db.delete(history)
        with self.assertRaises(ValueError):
            self.db.flush()
        self.db.rollback()

    def test_05_web_rbac_and_history_are_exposed(self):
        action = create_corrective_action(
            self.db, quality_review_id=self.review.id, responsible_user_id=self.base.analyst1.id,
            due_date=self.now.date(), priority="MOYENNE", comment=None, actor=self.base.actor(self.base.admin),
        )
        self.db.commit()
        with TestClient(test_lot_6a._test_app(self.db)) as client:
            client.get("/_test/login/ADMIN_TECHNIQUE")
            self.assertEqual(client.get("/web/corrective-actions").status_code, 200)
            self.assertEqual(client.post("/web/corrective-actions", data={
                "quality_review_id": str(self.review.id),
                "responsible_user_id": str(self.base.analyst2.id),
                "due_date": self.now.date().isoformat(),
                "priority": "HAUTE",
                "comment": "Action créée par le formulaire.",
            }, follow_redirects=False).status_code, 303)
            self.assertEqual(client.post(f"/web/corrective-actions/{action.id}", data={"status": BLOCKED}, follow_redirects=False).status_code, 303)
            client.get("/_test/login/ANALYSTE_CONFORMITE")
            self.assertEqual(client.get("/web/corrective-actions").status_code, 200)
            self.assertEqual(client.post(f"/web/corrective-actions/{action.id}", data={"status": IN_PROGRESS}, follow_redirects=False).status_code, 303)
            client.get("/_test/login/CONSULTATION")
            self.assertEqual(client.get("/web/corrective-actions").status_code, 403)


if __name__ == "__main__":
    unittest.main()
