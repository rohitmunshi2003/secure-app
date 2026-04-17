# utils/validator.py
import re

def validate_username(username):
    """3-20 characters, alphanumeric + underscore"""
    # This function checks if the username is valid
    # It must be 3 to 20 characters long
    # Only letters, numbers, and underscores are allowed
    return bool(re.fullmatch(r'\w{3,20}', username))
    # re.fullmatch checks if the ENTIRE string matches the pattern
    # \w means any letter, number, or underscore
    # {3,20} means length must be between 3 and 20 characters
    # bool() converts the match object to True or False

def validate_email(email):
    """Basic email validation"""
    # This function checks if an email is valid in a simple way
    # It doesn't guarantee the email exists, just that it looks like one
    return bool(re.fullmatch(r"[^@]+@[^@]+\.[^@]+", email))
    # [^@]+ means one or more characters that are NOT '@'
    # @ means the literal '@' symbol
    # \. means a literal dot '.'
    # So this ensures the email has something like 'user@domain.com'
    # bool() converts the match object to True or False

def validate_password_strength(password):
    """Minimum 12 chars, uppercase, lowercase, number, special"""
    # This function checks if a password is strong enough
    
    if len(password) < 12:
        return False
        # If password is shorter than 12, it's weak → return False
    
    if not re.search(r'[A-Z]', password):
        return False
        # Check if at least one uppercase letter exists
    
    if not re.search(r'[a-z]', password):
        return False
        # Check if at least one lowercase letter exists
    
    if not re.search(r'\d', password):
        return False
        # Check if at least one number exists
        # \d matches any digit (0-9)
    
    if not re.search(r'[!@#$%^&*]', password):
        return False
        # Check if at least one special character exists
        # Only these special characters are allowed: !@#$%^&*
    
    return True
    # If all checks pass, the password is strong → return True