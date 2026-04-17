from functools import wraps
from flask import g, redirect, url_for, flash

def require_role(*roles):
    """
    Decorator to enforce RBAC (Role-Based Access Control) on a route.
    Usage example:
        @require_role('admin', 'user')
        def dashboard(): ...
    Only users with roles listed in `roles` can access the route.
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # The actual wrapper function that runs before the route function
            user_role = g.get('user_role', None)
            # Retrieve the current user's role from Flask's 'g' object
            # If no role is found, default to None

            if user_role not in roles: # If the user's role is not allowed
                flash("You do not have permission to access this page.", "error") # Show an error message to the user
                return redirect(url_for('dashboard')) # Redirect the user to the dashboard or safe page

            return f(*args, **kwargs) # If role is allowed, call the original route function with all arguments

        return wrapper # Return the wrapped function to replace the original route
    return decorator # Return the decorator function to be applied to the route