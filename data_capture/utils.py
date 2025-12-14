import os
import PyPDF2
import pdfplumber
import pandas as pd
from PIL import Image
from django.conf import settings

# Optional: pytesseract for OCR (requires Tesseract OCR to be installed)
try:
    import pytesseract
    PYTESSERACT_AVAILABLE = True
except ImportError:
    PYTESSERACT_AVAILABLE = False


def extract_pdf_data(file_path):
    """Extract text data from PDF file"""
    text_data = []
    
    try:
        # Try using pdfplumber first (better for tables)
        with pdfplumber.open(file_path) as pdf:
            for page in pdf.pages:
                text = page.extract_text()
                if text:
                    text_data.append({
                        'page': page.page_number,
                        'text': text
                    })
    except Exception as e:
        print(f"Error with pdfplumber: {e}")
        # Fallback to PyPDF2
        try:
            with open(file_path, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                for page_num, page in enumerate(pdf_reader.pages, 1):
                    text = page.extract_text()
                    if text:
                        text_data.append({
                            'page': page_num,
                            'text': text
                        })
        except Exception as e2:
            print(f"Error with PyPDF2: {e2}")
    
    return {
        'type': 'pdf',
        'pages': len(text_data),
        'content': text_data
    }


def extract_excel_data(file_path):
    """Extract data from Excel file"""
    try:
        # Read all sheets
        excel_file = pd.ExcelFile(file_path)
        sheets_data = {}
        
        for sheet_name in excel_file.sheet_names:
            df = pd.read_excel(file_path, sheet_name=sheet_name)
            # Convert DataFrame to dictionary
            sheets_data[sheet_name] = {
                'columns': df.columns.tolist(),
                'rows': df.values.tolist(),
                'row_count': len(df)
            }
        
        return {
            'type': 'excel',
            'sheets': sheets_data
        }
    except Exception as e:
        print(f"Error extracting Excel data: {e}")
        return {
            'type': 'excel',
            'error': str(e)
        }


def extract_image_data(file_path):
    """Extract text from image using OCR"""
    try:
        # Note: pytesseract requires Tesseract OCR to be installed
        # For production, you might want to use a cloud OCR service
        image = Image.open(file_path)
        
        # Try OCR if pytesseract is available and configured
        if PYTESSERACT_AVAILABLE:
            try:
                text = pytesseract.image_to_string(image)
                return {
                    'type': 'image',
                    'text': text,
                    'format': image.format,
                    'size': image.size
                }
            except Exception:
                # If OCR fails, return image metadata
                return {
                    'type': 'image',
                    'format': image.format,
                    'size': image.size,
                    'mode': image.mode,
                    'note': 'OCR not available. Install Tesseract OCR for text extraction.'
                }
        else:
            # If pytesseract is not installed, return image metadata
            return {
                'type': 'image',
                'format': image.format,
                'size': image.size,
                'mode': image.mode,
                'note': 'OCR not available. Install pytesseract and Tesseract OCR for text extraction.'
            }
    except Exception as e:
        print(f"Error extracting image data: {e}")
        return {
            'type': 'image',
            'error': str(e)
        }




