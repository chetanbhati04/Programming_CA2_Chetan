# Quick Start Guide

## Step 1: Install Dependencies

```bash
pip install -r requirements.txt
```

## Step 2: Set Up MongoDB

Make sure MongoDB is running on your system. Default connection is `mongodb://localhost:27017/`

## Step 3: Run Migrations

```bash
python manage.py makemigrations
python manage.py migrate
```

## Step 4: Create Superuser (Optional)

```bash
python manage.py createsuperuser
```

## Step 5: Run the Server

```bash
python manage.py runserver
```

## Step 6: Access the Application

1. Open browser: `http://127.0.0.1:8000/`
2. You'll be redirected to login page
3. Register a new account or login
4. Start uploading files or scraping websites!

## Troubleshooting

### MongoDB Connection Error
If you see MongoDB errors, you can temporarily use SQLite:
1. Open `Evidence_management/setting.py`
2. Comment out the MongoDB DATABASES configuration
3. Uncomment the SQLite DATABASES configuration
4. Run migrations again

### Image OCR Not Working
Install Tesseract OCR:
- Windows: Download from GitHub
- Linux: `sudo apt-get install tesseract-ocr`
- macOS: `brew install tesseract`

The system will still work without Tesseract, but image text extraction won't be available.


