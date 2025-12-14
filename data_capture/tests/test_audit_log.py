from django.test import TestCase, RequestFactory
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser

from data_capture.models import AuditLog
from data_capture.security import log_audit_event


User = get_user_model()


class AuditLogModelTests(TestCase):
    """
    Basic tests for the AuditLog model itself.
    """

    def setUp(self):
        self.user = User.objects.create_user(
            username="audituser",
            email="audit@example.com",
            password="auditpass123",
        )

    def test_create_audit_log_with_user(self):
        entry = AuditLog.objects.create(
            user=self.user,
            action="upload_success",
            message="File test.pdf uploaded successfully.",
            ip_address="127.0.0.1",
            user_agent="TestAgent/1.0",
        )

        self.assertIsNotNone(entry.id)
        self.assertEqual(entry.user, self.user)
        self.assertEqual(entry.action, "upload_success")
        self.assertIn("uploaded", entry.message)
        self.assertEqual(entry.ip_address, "127.0.0.1")
        self.assertEqual(entry.user_agent, "TestAgent/1.0")

    def test_create_audit_log_without_user(self):
        entry = AuditLog.objects.create(
            user=None,
            action="anonymous_access",
            message="Anonymous user attempted something.",
            ip_address="10.0.0.1",
            user_agent="AnonAgent/2.0",
        )

        self.assertIsNotNone(entry.id)
        self.assertIsNone(entry.user)
        self.assertEqual(entry.action, "anonymous_access")
        self.assertEqual(entry.ip_address, "10.0.0.1")


class LogAuditEventIntegrationTests(TestCase):
    """
    Integration tests for log_audit_event() using real AuditLog model.
    """

    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(
            username="loguser",
            email="log@example.com",
            password="logpass123",
        )

    def test_log_audit_event_with_authenticated_user(self):
        # Build a fake request
        request = self.factory.get(
            "/dummy-path/",
            HTTP_USER_AGENT="TestAgent/1.0",
            REMOTE_ADDR="127.0.0.1",
        )
        request.user = self.user

        log_audit_event(request, "upload_attempt", "Testing upload event")

        self.assertEqual(AuditLog.objects.count(), 1)
        entry = AuditLog.objects.first()

        self.assertEqual(entry.user, self.user)
        self.assertEqual(entry.action, "upload_attempt")
        self.assertIn("Testing upload event", entry.message)
        self.assertEqual(entry.ip_address, "127.0.0.1")
        self.assertEqual(entry.user_agent, "TestAgent/1.0")

    def test_log_audit_event_with_anonymous_user(self):
        request = self.factory.get(
            "/dummy-path-anon/",
            HTTP_USER_AGENT="AnonAgent/9.9",
            REMOTE_ADDR="192.168.1.10",
        )
        request.user = AnonymousUser()

        log_audit_event(request, "anon_action", "Anonymous test event")

        self.assertEqual(AuditLog.objects.count(), 1)
        entry = AuditLog.objects.first()

        self.assertIsNone(entry.user)
        self.assertEqual(entry.action, "anon_action")
        self.assertIn("Anonymous test event", entry.message)
        self.assertEqual(entry.ip_address, "192.168.1.10")
        # user_agent should be stored, possibly truncated at 255 chars
        self.assertTrue(entry.user_agent.startswith("AnonAgent"))
        self.assertLessEqual(len(entry.user_agent), 255)

    def test_log_audit_event_prefers_remote_addr_over_x_forwarded_for(self):
        # Both headers set – should use REMOTE_ADDR first
        request = self.factory.get(
            "/dummy-path/",
            HTTP_USER_AGENT="DualAgent/1.0",
            REMOTE_ADDR="203.0.113.5",
            HTTP_X_FORWARDED_FOR="10.0.0.1",
        )
        request.user = self.user

        log_audit_event(request, "dual_ip_test", "Testing IP selection")

        entry = AuditLog.objects.first()
        self.assertEqual(entry.ip_address, "203.0.113.5")

        def test_log_audit_event_uses_x_forwarded_for_if_no_remote_addr(self):
        # Force REMOTE_ADDR to be empty so X_FORWARDED_FOR is used
            request = self.factory.get(
            "/dummy-path/",
            HTTP_USER_AGENT="ForwardedAgent/1.0",
            REMOTE_ADDR="",  # <- empty so 'or' falls back
            HTTP_X_FORWARDED_FOR="10.10.10.10",
        )
            request.user = self.user

            log_audit_event(request, "forwarded_ip_test", "Testing forwarded IP")

            entry = AuditLog.objects.first()
            self.assertEqual(entry.ip_address, "10.10.10.10")
