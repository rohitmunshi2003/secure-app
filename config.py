# Flask
SECRET_KEY = "supersecretkey123!@#"
MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 MB

# Email (SMTP)
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_ADDRESS = "dolphinxyz33@gmail.com"
EMAIL_PASSWORD = "cako wexy sddw rihb"  # app password

# App settings
SESSION_TIMEOUT = 1800  # 30 minutes

# Security 
MAX_ATTEMPTS_PER_MINUTE = 10
WINDOW_SECONDS = 60

# File handling 
DATA_DIR = "data"
UPLOAD_DIR = "data/documents"
ALLOWED_EXTENSIONS = {"txt", "pdf", "docx", "xlsx", "png", "jpg", "jpeg"}

# Security / Login 
MAX_FAILED_ATTEMPTS = 5
ACCOUNT_LOCK_TIME = 15 * 60  # 15 minutes

# OTP 
OTP_EXPIRY_SECONDS = 600  # 10 minutes

UPLOAD_DIR = "uploads"

SSL_CERT = "cert.pem"
SSL_KEY = "key.pem"

OTP_EMAIL_SUBJECT = "Password Reset OTP"

FILE_VERSION_FORMAT = "{filename}_v{version}.enc"