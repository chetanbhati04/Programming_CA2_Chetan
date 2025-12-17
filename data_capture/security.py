import subprocess
import json
import re
import html
from pathlib import Path

from django.conf import settings

from PyPDF2 import PdfReader, PdfWriter
from PIL import Image

from .models import AuditLog


#  Malware scanning

def scan_file_for_malware(file_path: str):
    """
    Scan the file using ClamAV (clamscan).
    Returns: (status, detail)
      status: True = clean, False = infected, None = scanner unavailable/error
      detail: human-readable message
    """
    try:
        result = subprocess.run(
            ['clamscan', '--no-summary', file_path],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except FileNotFoundError:
        # clamscan not installed / not in PATH
        return None, "Malware scanner (clamscan) not found on this system."
    except Exception as e:
        return None, f"Error running malware scan: {e}"

    if result.returncode == 0:
        return True, "File is clean (ClamAV)."
    elif result.returncode == 1:
        return False, result.stdout or "Malware detected by ClamAV."
    else:
        return None, result.stderr or "Unknown error from malware scanner."

#Excel sanitizing
SCRIPT_RE = re.compile(r"<\s*script.*?>.*?<\s*/\s*script\s*>", re.IGNORECASE | re.DOTALL)
TAG_RE = re.compile(r"<[^>]+>")

def sanitize_text(value: str) -> str:
    """Basic output sanitization for extracted strings (Excel, OCR text, etc.)."""
    if value is None:
        return value
    if not isinstance(value, str):
        return value

    # Remove <script>...</script>
    value = SCRIPT_RE.sub("", value)

    # Remove any remaining HTML tags
    value = TAG_RE.sub("", value)

    # Escape special HTML characters to avoid XSS in templates
    value = html.escape(value)

    # Optional: remove obvious SQL injection patterns (demo-level)
    value = value.replace("DROP TABLE", "[REMOVED]").replace("drop table", "[REMOVED]")

    return value

def sanitize_extracted_data(obj):
    """Recursively sanitize extracted JSON-like data (dict/list/str)."""
    if isinstance(obj, dict):
        return {k: sanitize_extracted_data(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [sanitize_extracted_data(x) for x in obj]
    if isinstance(obj, str):
        return sanitize_text(obj)
    return obj
# File sanitization

def sanitize_file(file_path: str, source_type: str):
    p = Path(file_path)

    # Only sanitize pdf + image uploads
    if source_type == 'pdf':
        try:
            reader = PdfReader(str(p))
            writer = PdfWriter()
            for page in reader.pages:
                writer.add_page(page)

            # Overwrite original file with sanitized version
            with open(str(p), 'wb') as f_out:
                writer.write(f_out)

            return True, str(p), "PDF sanitized successfully."
        except Exception as e:
            return False, str(p), f"PDF sanitization failed: {e}"

    elif source_type == 'image':
        try:
            img = Image.open(str(p))
            # Convert to RGB to avoid weird modes, then save back
            if img.mode not in ('RGB', 'RGBA'):
                img = img.convert('RGB')

            img.save(str(p), optimize=True)
            return True, str(p), "Image sanitized successfully."
        except Exception as e:
            return False, str(p), f"Image sanitization failed: {e}"

    # For other types (e.g. excel), just return unchanged
    return True, str(p), "No sanitization applied for this file type."


# Audit logging helper

def log_audit_event(request, action: str, message: str = ""):
    """
    Create an AuditLog entry.
    Safe to call from any view.
    """
    ip = request.META.get('REMOTE_ADDR') or request.META.get('HTTP_X_FORWARDED_FOR')
    ua = request.META.get('HTTP_USER_AGENT', '')[:255]

    AuditLog.objects.create(
        user=request.user if request.user.is_authenticated else None,
        action=action,
        message=message,
        ip_address=ip,
        user_agent=ua,
    )
