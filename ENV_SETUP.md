# Environment Variables Setup

## Create .env File

Create a `.env` file in the project root directory with the following content:

```env
# MongoDB Configuration
MONGODB_HOST=mongodb://localhost:27017/
MONGODB_PORT=27017

# Django Secret Key (change this in production!)
SECRET_KEY=django-insecure-your-secret-key-change-in-production

# Debug Mode (set to False in production)
DEBUG=True

# Allowed Hosts (comma-separated for production)
# ALLOWED_HOSTS=localhost,127.0.0.1,yourdomain.com
```

## Quick Setup

1. Copy the example file:
   ```bash
   copy env.example .env
   ```
   (On Linux/Mac: `cp env.example .env`)

2. Edit `.env` file with your actual values

## MongoDB Configuration Examples

### Local MongoDB
```env
MONGODB_HOST=mongodb://localhost:27017/
MONGODB_PORT=27017
```

### MongoDB Atlas (Cloud)
```env
MONGODB_HOST=mongodb+srv://username:password@cluster.mongodb.net/
MONGODB_PORT=27017
```

### MongoDB with Authentication
```env
MONGODB_HOST=mongodb://username:password@localhost:27017/
MONGODB_PORT=27017
```

## Generate Secret Key

To generate a secure secret key, run:
```bash
python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
```

Then copy the output to `SECRET_KEY` in your `.env` file.

## Notes

- The `.env` file is already in `.gitignore` for security
- Never commit your `.env` file to version control
- Use `env.example` as a template for team members

