import subprocess
import json
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


# File sanitization

def sanitize_file(file_path: str, source_type: str):
    """
    Sanitize uploaded files BEFORE processing:
    - pdf: rebuild PDF with PyPDF2 (removes scripts, metadata, etc.)
    - image: reopen & resave via Pillow (drops metadata)
    Other types: returned unchanged.
    Returns: (success, sanitized_path, message)
    """
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
