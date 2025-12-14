# data_capture/models.py
from django.db import models
from django.conf import settings
import json


class DataSource(models.Model):
    """Model to track data sources"""
    SOURCE_TYPES = [
        ('pdf', 'PDF'),
        ('excel', 'Excel'),
        ('image', 'Image'),
        ('website', 'Website'),
        ('other', 'Other'),
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    source_type = models.CharField(max_length=20, choices=SOURCE_TYPES)
    file_name = models.CharField(max_length=255, null=True, blank=True)
    website_url = models.URLField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # SHA-256 hash of the uploaded file contents
    file_hash = models.CharField(max_length=64, null=True, blank=True)

    def __str__(self):
        return f"{self.get_source_type_display()} - {self.user.username}"


class ExtractedData(models.Model):
    """Extracted content for each DataSource"""
    source = models.ForeignKey(
        DataSource,
        on_delete=models.CASCADE,
        related_name='extracted_items'
    )
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    data = models.TextField()  # store JSON/text
    created_at = models.DateTimeField(auto_now_add=True)

    # SHA-256 hash of the JSON/text stored in `data`
    content_hash = models.CharField(max_length=64, null=True, blank=True)

    def __str__(self):
        return f"ExtractedData #{self.pk} for {self.source}"

    @property
    def parsed(self):
        """Return JSON if possible, otherwise raw text."""
        try:
            return json.loads(self.data)
        except Exception:
            return self.data

class ContactMessage(models.Model):
    """Message sent by investigator/user to admin."""
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        help_text="User who sent the message (if logged in)."
    )
    name = models.CharField(max_length=100)
    email = models.EmailField()
    subject = models.CharField(max_length=200)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    is_resolved = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.subject} - {self.name} ({self.created_at:%Y-%m-%d})"

class AuditLog(models.Model):
    """Security audit log for important events (uploads, malware, errors)."""

    ACTION_CHOICES = [
        ('upload_attempt', 'Upload attempt'),
        ('upload_blocked_malware', 'Upload blocked – malware detected'),
        ('upload_success', 'Upload success'),
        ('malware_scanner_unavailable', 'Malware scanner unavailable'),
        ('sanitization_failed', 'File sanitization failed'),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
    message = models.TextField(blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        user_str = self.user.username if self.user else "Anonymous"
        return f"[{self.created_at:%Y-%m-%d %H:%M}] {self.action} by {user_str}"