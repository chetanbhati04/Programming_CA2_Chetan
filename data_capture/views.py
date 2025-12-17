from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from .forms import ContactForm

from .models import DataSource, ExtractedData
from .utils import (extract_pdf_data,extract_excel_data,extract_image_data,)
from .security import scan_file_for_malware, sanitize_file, log_audit_event, sanitize_extracted_data
import os
import json
import hashlib


@login_required
def home(request):
    """Dashboard – show tools + recent uploads for this user."""
    user_sources = (
        DataSource.objects
        .filter(user=request.user)
        .order_by('-created_at')
        .prefetch_related('extracted_items')
    )
    return render(request, 'data_capture/home.html', {
        'sources': user_sources,
    })

@login_required
def delete_source(request, pk):
    source = get_object_or_404(DataSource, pk=pk, user=request.user)

    if request.method != 'POST':
        # Don't allow GET to perform delete
        return redirect('home')

    filename = source.file_name or "(no filename)"

    # 🔐 Audit log
    log_audit_event(
        request,
        action='upload_undo',
        message=f"User requested undo for source #{source.id} ({filename})."
    )

# 1) Delete file from disk
    if source.file_name:
        file_path = settings.MEDIA_ROOT / 'uploads' / source.file_name
        try:
            if file_path.exists():
                file_path.unlink()
        except Exception as e:
            # We log this in the audit message to be safe, but do not block the undo.
            log_audit_event(
                request,
                action='sanitization_failed',  # reuse or create a new action if you want
                message=f"Failed to delete file on undo for source #{source.id}: {e}"
            )

# 2) Delete extracted data rows linked to this source
    ExtractedData.objects.filter(source=source).delete()

# 3) Delete the DataSource itself
    source.delete()

    messages.success(request, "Your upload has been removed .")
    return redirect('home')


@login_required
def upload_file(request):
    """Handle file upload with security: validation, malware scan, sanitization, audit logs."""
    if request.method != 'POST':
        return redirect('home')

    uploaded_file = request.FILES.get('file')
    source_type = request.POST.get('source_type', 'pdf')  # default pdf

    # --------- Audit: upload attempt ----------
    log_audit_event(request, 'upload_attempt', f"Attempting to upload file: {uploaded_file.name if uploaded_file else 'None'}")

    if not uploaded_file:
        messages.error(request, 'Please select a file to upload.')
        return redirect('home')

    # Determine extension
    filename = uploaded_file.name
    if '.' in filename:
        file_extension = filename.rsplit('.', 1)[-1].lower()
    else:
        file_extension = ''

    valid_extensions = {
        'pdf': ['pdf'],
        'excel': ['xlsx', 'xls'],
        'image': ['png', 'jpg', 'jpeg', 'gif', 'bmp'],
    }

    # Backend validation: ensure type matches extension
    if source_type not in valid_extensions or file_extension not in valid_extensions[source_type]:
        messages.error(
            request,
            f"File format incorrect. Please upload a valid {source_type.upper()} file."
        )
        return redirect('home')

    # Ensure uploads folder exists
    media_dir = settings.MEDIA_ROOT / 'uploads'
    media_dir.mkdir(parents=True, exist_ok=True)

    # Save uploaded file to disk (raw)
    file_path = media_dir / uploaded_file.name
    with open(file_path, 'wb+') as dest:
        for chunk in uploaded_file.chunks():
            dest.write(chunk)

    file_path_str = str(file_path)

    # --------- Malware scan ----------
    scan_status, scan_detail = scan_file_for_malware(file_path_str)

    if scan_status is False:
        # Infected
        log_audit_event(request, 'upload_blocked_malware', f"{filename}: {scan_detail}")
        # Optionally delete the file
        try:
            os.remove(file_path_str)
        except OSError:
            pass

        messages.error(request, "Upload blocked: file appears to contain malware.")
        return redirect('home')

    elif scan_status is None:
        # Scanner missing or error
        log_audit_event(request, 'malware_scanner_unavailable', f"{filename}: {scan_detail}")
        # We still allow upload but we log the risk.

    # --------- Sanitization (pdf + image) ----------
    sanitized_ok, sanitized_path, sanitize_msg = sanitize_file(file_path_str, source_type)
    file_path_str = sanitized_path  # in case it ever changes in future

    if not sanitized_ok:
        log_audit_event(request, 'sanitization_failed', f"{filename}: {sanitize_msg}")
        messages.warning(
            request,
            "File uploaded, but sanitization failed. Proceed with caution."
        )
    else:
        # You may log success if you like (optional)
        pass

    # --------- Compute hash AFTER sanitization (optional but nice) ----------
    sha256 = hashlib.sha256()
    with open(file_path_str, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    file_hash = sha256.hexdigest()

        # --------- Extract data ----------
    extracted_data = None

    if source_type == 'pdf':
        extracted_data = extract_pdf_data(file_path_str)
    elif source_type == 'excel':
        extracted_data = extract_excel_data(file_path_str)
    elif source_type == 'image':
        extracted_data = extract_image_data(file_path_str)

    # ✅ sanitize AFTER extraction
    if extracted_data:
        extracted_data = sanitize_extracted_data(extracted_data)



  


    
    # --------- Create DataSource record ----------
    data_source = DataSource.objects.create(
        user=request.user,
        source_type=source_type,
        file_name=uploaded_file.name,
        file_hash=file_hash,  # if you added this field earlier
    )

    # --------- Save extracted data + log success ----------
    if extracted_data:
        data_json = json.dumps(extracted_data, default=str)

        # If you have ExtractedData & content hashes:
        try:
            content_hash = hashlib.sha256(data_json.encode('utf-8')).hexdigest()
            ExtractedData.objects.create(
                source=data_source,
                user=request.user,
                data=data_json,
                content_hash=content_hash,
            )
        except TypeError:
            
            pass

        log_audit_event(
            request,
            'upload_success',
            f"File {filename} uploaded and processed successfully."
        )
        messages.success(request, 'File uploaded successfully.')
    else:
        messages.error(request, 'Failed to upload file .')

    return redirect('home')

@login_required
def contact(request):
    """Contact page where investigator can send a message to admin."""
    if request.method == 'POST':
        form = ContactForm(request.POST)
        if form.is_valid():
            contact_msg = form.save(commit=False)
            contact_msg.user = request.user
            contact_msg.save()
            messages.success(request, "Your message has been sent to the admin.")
            return redirect('contact')
        else:
            messages.error(request, "Please correct the errors below.")
    else:
        # Pre-fill name and email from logged-in user if available
        initial = {}
        if request.user.is_authenticated:
            if request.user.get_full_name():
                initial['name'] = request.user.get_full_name()
            else:
                initial['name'] = request.user.username
            if getattr(request.user, 'email', None):
                initial['email'] = request.user.email
        form = ContactForm(initial=initial)

    return render(request, 'data_capture/contact.html', {'form': form})



@login_required
@login_required
def source_detail(request, pk):
    """Show one upload with its extracted data, nicely formatted per type."""
    source = get_object_or_404(DataSource, pk=pk, user=request.user)

    # Get the latest extracted record for this source
    extracted_obj = source.extracted_items.order_by('-created_at').first()

    pdf_pages = None
    excel_sheets = None
    image_data = None
    raw_data = None
    extracted_type = None

    if extracted_obj:
        raw_data = extracted_obj.data
        try:
            parsed = json.loads(extracted_obj.data)
        except Exception:
            parsed = None

        if isinstance(parsed, dict):
            extracted_type = parsed.get('type')

            if extracted_type == 'pdf':
                # Expecting: {'type': 'pdf', 'pages': N, 'content': [{page, text}, ...]}
                pdf_pages = parsed.get('content', [])

            elif extracted_type == 'excel':
                # Expecting: {'type': 'excel', 'sheets': {sheet_name: {...}}}
                sheets = parsed.get('sheets', {})
                excel_sheets = []
                for name, sheet in sheets.items():
                    excel_sheets.append({
                        'name': name,
                        'columns': sheet.get('columns', []),
                        'rows': sheet.get('rows', []),
                        'row_count': sheet.get('row_count', 0),
                    })

            elif extracted_type == 'image':
                # Just pass the whole dict to display details
                image_data = parsed

    image_url = None
    if source.source_type == "image" and source.file_name:
        image_url = settings.MEDIA_URL + "uploads/" + source.file_name

    context = {
        'source': source,
        'extracted_obj': extracted_obj,
        'extracted_type': extracted_type,
        'pdf_pages': pdf_pages,
        'excel_sheets': excel_sheets,
        'image_data': image_data,
        'raw_data': raw_data,
        'image_url': image_url,
    }

    return render(request, 'data_capture/source_detail.html', context)


@login_required
@csrf_exempt
def api_upload_file(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    uploaded_file = request.FILES.get('file')
    source_type = request.POST.get('source_type', 'pdf')

    if not uploaded_file:
        return JsonResponse({'error': 'No file provided'}, status=400)

    filename = uploaded_file.name
    file_extension = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''

    valid_extensions = {
        'pdf': ['pdf'],
        'excel': ['xlsx', 'xls'],
        'image': ['png', 'jpg', 'jpeg', 'gif', 'bmp'],
    }

    if source_type not in valid_extensions or file_extension not in valid_extensions[source_type]:
        return JsonResponse(
            {'error': f"File format incorrect. Please upload a valid {source_type.upper()} file."},
            status=400
        )

    media_dir = settings.MEDIA_ROOT / 'uploads'
    media_dir.mkdir(parents=True, exist_ok=True)

    file_path = media_dir / filename
    with open(file_path, 'wb+') as dest:
        for chunk in uploaded_file.chunks():
            dest.write(chunk)


    sanitized_ok, sanitized_path, sanitize_msg = sanitize_file(str(file_path), source_type)
    if sanitized_ok:
        log_audit_event(request, 'sanitization_success', f"{filename}: {sanitize_msg}")
    else:
        log_audit_event(request, 'sanitization_failed', f"{filename}: {sanitize_msg}")

    file_path = sanitized_path
    # --------- Extract data ----------
    extracted_data = None
    if source_type == 'pdf':
        extracted_data = extract_pdf_data(str(file_path))
    elif source_type == 'excel':
        extracted_data = extract_excel_data(str(file_path))
    elif source_type == 'image':
        extracted_data = extract_image_data(str(file_path))

    # ✅ sanitize AFTER extraction
    if extracted_data:
        extracted_data = sanitize_extracted_data(extracted_data)

        data_source = DataSource.objects.create(
            user=request.user,
            source_type=source_type,
            file_name=filename,
        )

        ExtractedData.objects.create(
            source=data_source,
            user=request.user,
            data=json.dumps(extracted_data, default=str),
        )

        return JsonResponse({
            'message': 'File uploaded and processed successfully',
            'source_id': data_source.id,
            'data': extracted_data,
        })

    return JsonResponse({'error': 'Failed to extract data'}, status=500)

