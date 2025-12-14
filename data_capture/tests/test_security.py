from django.test import SimpleTestCase, TestCase
from unittest.mock import patch, MagicMock, mock_open
from types import SimpleNamespace
from pathlib import Path

# relative import, works even if app name changes
from data_capture import security


class DummyTest(SimpleTestCase):
    """
    Simple sanity check that Django is discovering this module.
    If this doesn't run, the problem is with test discovery, not the tests.
    """
    def test_dummy_works(self):
        self.assertEqual(1 + 1, 2)


class ScanFileForMalwareTests(SimpleTestCase):
    """
    Tests for scan_file_for_malware()
    """

    @patch("data_capture.security.subprocess.run")
    def test_scan_file_for_malware_clean(self, mock_run):
        # Simulate clamscan returning 0 (clean)
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "OK"
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        status, detail = security.scan_file_for_malware("dummy/path/file.txt")

        self.assertTrue(status)
        self.assertIn("clean", detail.lower())
        mock_run.assert_called_once()

    @patch("data_capture.security.subprocess.run")
    def test_scan_file_for_malware_infected(self, mock_run):
        # Simulate clamscan returning 1 (infected)
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = "FOUND: EICAR-Test-File"
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        status, detail = security.scan_file_for_malware("dummy/path/eicar.com")

        self.assertFalse(status)
        self.assertIn("eicar", detail.lower())
        mock_run.assert_called_once()

    @patch("data_capture.security.subprocess.run")
    def test_scan_file_for_malware_unknown_error(self, mock_run):
        # Simulate clamscan returning 2 (error)
        mock_proc = MagicMock()
        mock_proc.returncode = 2
        mock_proc.stdout = ""
        mock_proc.stderr = "Some error"
        mock_run.return_value = mock_proc

        status, detail = security.scan_file_for_malware("dummy/path/file.txt")

        self.assertIsNone(status)
        self.assertIn("error", detail.lower())
        mock_run.assert_called_once()

    @patch("data_capture.security.subprocess.run")
    def test_scan_file_for_malware_scanner_missing(self, mock_run):
        # Simulate clamscan binary not found
        mock_run.side_effect = FileNotFoundError()

        status, detail = security.scan_file_for_malware("dummy/path/file.txt")

        self.assertIsNone(status)
        self.assertIn("not found", detail.lower())


class SanitizeFileTests(SimpleTestCase):
    """
    Tests for sanitize_file()
    """

    @patch("builtins.open", new_callable=mock_open)
    @patch("data_capture.security.PdfWriter")
    @patch("data_capture.security.PdfReader")
    def test_sanitize_pdf_success(self, mock_reader, mock_writer, mock_file_open):
        # Simulate a PDF with two pages
        mock_reader.return_value.pages = [MagicMock(), MagicMock()]
        mock_writer_instance = MagicMock()
        mock_writer.return_value = mock_writer_instance

        ok, sanitized_path, msg = security.sanitize_file("/tmp/test.pdf", "pdf")

        expected_path = str(Path("/tmp/test.pdf"))  # OS-correct path
        self.assertTrue(ok)
        self.assertEqual(sanitized_path, expected_path)
        self.assertIn("sanitized", msg.lower())

        mock_reader.assert_called_once()
        mock_writer_instance.add_page.assert_called()
        mock_writer_instance.write.assert_called_once()
        mock_file_open.assert_called_once()

    @patch("builtins.open", new_callable=mock_open)
    @patch("data_capture.security.PdfWriter")
    @patch("data_capture.security.PdfReader")
    def test_sanitize_pdf_failure(self, mock_reader, mock_writer, mock_file_open):
        # Make PdfReader raise an error
        mock_reader.side_effect = Exception("broken pdf")

        ok, sanitized_path, msg = security.sanitize_file("/tmp/bad.pdf", "pdf")

        expected_path = str(Path("/tmp/bad.pdf"))
        self.assertFalse(ok)
        self.assertEqual(sanitized_path, expected_path)
        self.assertIn("failed", msg.lower())

    @patch("data_capture.security.Image.open")
    def test_sanitize_image_success(self, mock_open_img):
        mock_img = MagicMock()
        mock_img.mode = "RGB"
        mock_open_img.return_value = mock_img

        ok, sanitized_path, msg = security.sanitize_file("/tmp/test.png", "image")

        expected_path = str(Path("/tmp/test.png"))
        self.assertTrue(ok)
        self.assertEqual(sanitized_path, expected_path)
        self.assertIn("sanitized", msg.lower())
        mock_open_img.assert_called_once_with(expected_path)
        mock_img.save.assert_called_once()

    @patch("data_capture.security.Image.open")
    def test_sanitize_image_failure(self, mock_open_img):
        mock_open_img.side_effect = Exception("image error")

        ok, sanitized_path, msg = security.sanitize_file("/tmp/bad.png", "image")

        expected_path = str(Path("/tmp/bad.png"))
        self.assertFalse(ok)
        self.assertEqual(sanitized_path, expected_path)
        self.assertIn("failed", msg.lower())

    def test_sanitize_other_type_no_change(self):
        ok, sanitized_path, msg = security.sanitize_file("/tmp/test.xlsx", "excel")

        expected_path = str(Path("/tmp/test.xlsx"))
        self.assertTrue(ok)
        self.assertEqual(sanitized_path, expected_path)
        self.assertIn("no sanitization", msg.lower())

        
class LogAuditEventTests(TestCase):
    """
    Tests for log_audit_event()
    Uses TestCase because it touches the database (AuditLog model).
    (We still mock AuditLog.objects.create so it doesn't depend on real data.)
    """

    @patch("data_capture.security.AuditLog.objects.create")
    def test_log_audit_event_authenticated_user(self, mock_create):
        user = SimpleNamespace(is_authenticated=True)
        request = SimpleNamespace(
            user=user,
            META={
                "REMOTE_ADDR": "127.0.0.1",
                "HTTP_USER_AGENT": "TestAgent/1.0",
            },
        )

        security.log_audit_event(request, "upload", "File uploaded")

        mock_create.assert_called_once()
        _, kwargs = mock_create.call_args

        self.assertEqual(kwargs["user"], user)
        self.assertEqual(kwargs["action"], "upload")
        self.assertEqual(kwargs["message"], "File uploaded")
        self.assertEqual(kwargs["ip_address"], "127.0.0.1")
        self.assertIn("TestAgent", kwargs["user_agent"])

    @patch("data_capture.security.AuditLog.objects.create")
    def test_log_audit_event_anonymous_user(self, mock_create):
        user = SimpleNamespace(is_authenticated=False)
        request = SimpleNamespace(
            user=user,
            META={
                "HTTP_X_FORWARDED_FOR": "10.0.0.1",
                "HTTP_USER_AGENT": "A" * 400,  # will be truncated to 255
            },
        )

        security.log_audit_event(request, "upload")

        _, kwargs = mock_create.call_args

        self.assertIsNone(kwargs["user"])
        self.assertEqual(kwargs["ip_address"], "10.0.0.1")
        self.assertEqual(kwargs["action"], "upload")
        self.assertEqual(kwargs["message"], "")
        self.assertLessEqual(len(kwargs["user_agent"]), 255)
