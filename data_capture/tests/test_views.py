from pathlib import Path
import json

from django.test import TestCase, override_settings
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from unittest.mock import patch, MagicMock

from data_capture.models import DataSource, ExtractedData

User = get_user_model()

# ---------- Helpers ----------

def create_test_user():
    return User.objects.create_user(
        username="testuser",
        email="test@example.com",
        password="testpass123"
    )


# ---------- HOME VIEW TESTS ----------

class HomeViewTests(TestCase):
    def setUp(self):
        self.user = create_test_user()
        self.client.force_login(self.user)

    def test_home_lists_only_user_sources(self):
        # sources for this user
        ds1 = DataSource.objects.create(user=self.user, source_type="pdf", file_name="a.pdf")
        ds2 = DataSource.objects.create(user=self.user, source_type="excel", file_name="b.xlsx")

        # source for another user
        other_user = User.objects.create_user(
            username="other",
            email="other@example.com",
            password="pass1234"
        )
        DataSource.objects.create(user=other_user, source_type="pdf", file_name="c.pdf")

        # URL name assumed: 'home'
        url = reverse("home")
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        sources = list(response.context["sources"])
        self.assertEqual(len(sources), 2)
        self.assertIn(ds1, sources)
        self.assertIn(ds2, sources)


# ---------- DELETE (UNDO) SOURCE TESTS ----------

class DeleteSourceViewTests(TestCase):
    def setUp(self):
        self.user = create_test_user()
        self.client.force_login(self.user)

    def _create_source_with_data(self):
        ds = DataSource.objects.create(
            user=self.user,
            source_type="pdf",
            file_name="test.pdf",
        )
        ExtractedData.objects.create(
            source=ds,
            user=self.user,
            data="{}",
        )
        return ds

    @patch("data_capture.views.log_audit_event")
    def test_delete_source_post_deletes_source_and_extracted_data(self, mock_log):
        ds = self._create_source_with_data()
        url = reverse("delete_source", args=[ds.pk])  # URL name assumed

        response = self.client.post(url)

        self.assertRedirects(response, reverse("home"))
        self.assertFalse(DataSource.objects.filter(pk=ds.pk).exists())
        self.assertFalse(ExtractedData.objects.filter(source=ds).exists())
        # At least one audit log (upload_undo)
        mock_log.assert_called()


# ---------- UPLOAD FILE VIEW TESTS ----------

@override_settings(MEDIA_ROOT=Path("test_media"))
class UploadFileViewTests(TestCase):
    def setUp(self):
        self.user = create_test_user()
        self.client.force_login(self.user)

    def _get_upload_url(self):
        # Your upload view is named 'upload_file' in redirects
        return reverse("upload_file")

    def _make_file(self, name="test.pdf", content=b"dummy", content_type="application/pdf"):
        return SimpleUploadedFile(name, content, content_type=content_type)

    @patch("data_capture.views.log_audit_event")
    def test_get_upload_redirects_to_home(self, mock_log):
        url = self._get_upload_url()
        response = self.client.get(url)
        self.assertRedirects(response, reverse("home"))
        # No log_audit_event on GET
        mock_log.assert_not_called()

    @patch("data_capture.views.log_audit_event")
    def test_upload_without_file_shows_error(self, mock_log):
        url = self._get_upload_url()
        response = self.client.post(url, {}, follow=True)

        self.assertRedirects(response, reverse("home"))
        self.assertEqual(DataSource.objects.count(), 0)
        # One audit: upload_attempt with filename None
        mock_log.assert_called_once()

    @patch("data_capture.views.log_audit_event")
    def test_upload_invalid_extension_rejected(self, mock_log):
        url = self._get_upload_url()
        bad_file = self._make_file(name="test.exe", content_type="application/octet-stream")

        response = self.client.post(
            url,
            {"file": bad_file, "source_type": "pdf"},
            follow=True,
        )

        self.assertRedirects(response, reverse("home"))
        self.assertEqual(DataSource.objects.count(), 0)
        # upload_attempt only
        mock_log.assert_called_once()

    @patch("data_capture.views.os.remove")
    @patch("data_capture.views.log_audit_event")
    @patch("data_capture.views.scan_file_for_malware")
    @patch("data_capture.views.sanitize_file")
    @patch("data_capture.views.extract_pdf_data")
    def test_infected_file_is_blocked(
        self,
        mock_extract_pdf,
        mock_sanitize,
        mock_scan,
        mock_log,
        mock_remove,
    ):
        url = self._get_upload_url()
        test_file = self._make_file("malicious.pdf")

        # Malware scan result: infected
        mock_scan.return_value = (False, "Malware detected")
        # sanitize_file should NOT be called in this case
        mock_sanitize.return_value = (True, "ignored", "ignored")
        mock_extract_pdf.return_value = {"type": "pdf", "content": []}

        response = self.client.post(
            url,
            {"file": test_file, "source_type": "pdf"},
            follow=True,
        )

        # User should be sent back to home with an error
        self.assertRedirects(response, reverse("home"))
        self.assertEqual(DataSource.objects.count(), 0)
        self.assertEqual(ExtractedData.objects.count(), 0)

        mock_scan.assert_called_once()
        mock_sanitize.assert_not_called()
        mock_extract_pdf.assert_not_called()
        mock_remove.assert_called()              # file deleted from disk
        self.assertGreaterEqual(mock_log.call_count, 1)  # at least one audit event

    @patch("data_capture.views.log_audit_event")
    @patch("data_capture.views.scan_file_for_malware")
    @patch("data_capture.views.sanitize_file")
    @patch("data_capture.views.extract_pdf_data")
    def test_clean_pdf_upload_creates_datasource_and_extracted_data(
        self,
        mock_extract_pdf,
        mock_sanitize,
        mock_scan,
        mock_log,
    ):
        url = self._get_upload_url()
        test_file = self._make_file("clean.pdf")

        # Malware scan OK
        mock_scan.return_value = (True, "File is clean")
        # Sanitization OK
        sanitized_path = str(Path("test_media") / "uploads" / "clean.pdf")
        mock_sanitize.return_value = (True, sanitized_path, "sanitized ok")
        # Extraction returns some structured data
        mock_extract_pdf.return_value = {
            "type": "pdf",
            "pages": 1,
            "content": [{"page": 1, "text": "Hello"}],
        }

        response = self.client.post(
            url,
            {"file": test_file, "source_type": "pdf"},
            follow=True,
        )

        self.assertRedirects(response, reverse("home"))
        self.assertEqual(DataSource.objects.count(), 1)
        self.assertEqual(ExtractedData.objects.count(), 1)

        ds = DataSource.objects.first()
        ex = ExtractedData.objects.first()
        self.assertEqual(ds.user, self.user)
        self.assertEqual(ex.source, ds)
        self.assertEqual(ex.user, self.user)

        mock_scan.assert_called_once()
        mock_sanitize.assert_called_once()
        mock_extract_pdf.assert_called_once()
        # At least one 'upload_attempt' and one 'upload_success'
        self.assertGreaterEqual(mock_log.call_count, 2)


# ---------- CONTACT VIEW TESTS ----------

class ContactViewTests(TestCase):
    def setUp(self):
        self.user = create_test_user()
        self.client.force_login(self.user)

    def test_get_contact_prefills_form(self):
        url = reverse("contact")
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        form = response.context["form"]
        # Name should be prefilled as full name or username
        self.assertIn("name", form.initial)
        self.assertIn("email", form.initial)

    def test_post_valid_contact_creates_message(self):
        url = reverse("contact")
        data = {
            "name": "Test User",
            "email": "test@example.com",
            "subject": "Hello",
            "message": "This is a test",
        }

        response = self.client.post(url, data, follow=True)
        self.assertEqual(response.status_code, 200)
        # Success message should be set
        messages = list(response.context["messages"])
        self.assertTrue(any("Your message has been sent" in str(m) for m in messages))


# ---------- SOURCE DETAIL VIEW TESTS ----------

class SourceDetailViewTests(TestCase):
    def setUp(self):
        self.user = create_test_user()
        self.client.force_login(self.user)

    def test_source_detail_for_pdf_parses_data(self):
        ds = DataSource.objects.create(
            user=self.user,
            source_type="pdf",
            file_name="test.pdf",
        )
        extracted_payload = {
            "type": "pdf",
            "pages": 1,
            "content": [{"page": 1, "text": "Hello PDF"}],
        }
        ExtractedData.objects.create(
            source=ds,
            user=self.user,
            data=json.dumps(extracted_payload),
        )

        url = reverse("source_detail", args=[ds.pk])
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["source"], ds)
        self.assertEqual(response.context["extracted_type"], "pdf")
        self.assertEqual(len(response.context["pdf_pages"]), 1)


# ---------- API UPLOAD VIEW TESTS ----------

@override_settings(MEDIA_ROOT=Path("test_media_api"))
class ApiUploadFileViewTests(TestCase):
    def setUp(self):
        self.user = create_test_user()
        self.client.force_login(self.user)

    def _get_api_url(self):
        return reverse("api_upload_file")

    def _make_file(self, name="test.pdf", content=b"dummy", content_type="application/pdf"):
        return SimpleUploadedFile(name, content, content_type=content_type)

    def test_api_get_not_allowed(self):
        url = self._get_api_url()
        response = self.client.get(url)
        self.assertEqual(response.status_code, 405)

    def test_api_no_file_returns_400(self):
        url = self._get_api_url()
        response = self.client.post(url, {}, follow=True)
        self.assertEqual(response.status_code, 400)

    def test_api_invalid_extension_returns_400(self):
        url = self._get_api_url()
        bad_file = self._make_file(name="test.exe", content_type="application/octet-stream")

        response = self.client.post(
            url,
            {"file": bad_file, "source_type": "pdf"},
        )
        self.assertEqual(response.status_code, 400)

    @patch("data_capture.views.extract_pdf_data")
    def test_api_valid_pdf_returns_success_json(self, mock_extract_pdf):
        url = self._get_api_url()
        file_obj = self._make_file("api_test.pdf")

        mock_extract_pdf.return_value = {
            "type": "pdf",
            "pages": 1,
            "content": [{"page": 1, "text": "Hello API"}],
        }

        response = self.client.post(
            url,
            {"file": file_obj, "source_type": "pdf"},
        )

        self.assertEqual(response.status_code, 200)
        body = json.loads(response.content)
        self.assertIn("message", body)
        self.assertEqual(body["message"], "File uploaded and processed successfully")
        self.assertIn("source_id", body)
        self.assertIn("data", body)
        self.assertEqual(DataSource.objects.count(), 1)
        self.assertEqual(ExtractedData.objects.count(), 1)
