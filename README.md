### SECURE FILE MANAGEMENT APP

## PROJECT OVERVIEW
This is a secure file management web application developed in Python using Flask.  

The application allows users/guests to:
-Register and login with secure authentication.
-To make a difference in user registration and guest registration, the user account needs to be approved by the admin whereas guest doesnt need approval.
-Upload, download, delete, and share files. These can be done by the user only if the user is the owner of the file or the owner has shared access with that user. Guest can only view and download the file that has been shared to guest.
-Reset Passwords using OTP sent to registered email. OTP is valid for 10 minutes only. This is for user as well as for guest.
-Maintain session security with HttpOnly, Secure, and SameSite cookies.
-Restrict access based on user roles (user vs admin) to prevent privilege escalation.
-Protect against common security vulnerabilities such as XSS, path traversal, and command injection.


## ADMIN USERNAME AND PASSWORD
Username: Dolphinxyz
Password: Rutgerssas33@


## FEATURES
1. **Authentication**
   - Brute force protection
   - Password complexity enforcement
   - Session management
   - Logout functionality
   - Password reset via OTP (time-limited)
2. **Authorization**
    - Horizontal Privilege enforcement
    - Vertical Privilege enforcement
    - Direct Object reference protection
    - Forced browsing protection
3. **Input Validation**
    - XSS prevention
    - Path traversal prevention
    - Command injection prevention
    - File upload restrictions (allowed file types: "pdf, txt, img, jpeg....", blocked file types: "exe, py, html, js")
4. **Session Security**
    - HttpOnly, Secure, SameSite cookies
    - Session timeout after 30 minutes
    - No session fixation vulnerability
5. **Configuration**
    - Security headers implemented (CSP, HSTS, X-Frame-Options, X-XSS-Protection)
    - Debug mode disabled in production
    - Proper TLS/SSL configuration (self signed certificate)


## SETUP INSTRUCTIONS
### Prerequisities
- Python 3.10+
- pip

### Installation
1. Clone the repository:


2. Install dependencies
pip install -r requirements.txt

3. Run the application:
python app.py

4. Open the browser and navigate to:
https://127.0.0.1:5000/



## How the appliation look and work on it

### Login and Register Page
- You can see a login page when you open the browser
- Below has the register option. Enter the information and create account. While creating account, you have the option to choose user/guest. If you chose to register as a user, then the account must be approved by the admin.
- Duirng the login, you can enter the username and password login.

### Reset password (Forget Password button)
When a user/guest want to reset password due to any reasons, they enter their username and email, then an 6 digit OTP is sent to that valid email, and OPT is verified and then user/guest is given a page to enter new password. Full strong password is checked during the reset password and suring registartion.

### Dashboard for user
- In the dasboard top left, there is an upload option to uplaod files.
- There is a dashboard button to redirect to dashboard and also a logout option to logout.
- User gets to see two sections in dashboard, one is "Uploaded by you" and another is "Shared with you".
- In Uploaded by you section, user can see the files uplaoded by that user. There that user has the option to share, download, as well as delete version.
- Owner of the file has the access to revoke the access to a file that was previously shared to someone. This can be done by clicking on share button fo that file. 
- -In Shared by you section, user can see the files shared to you which can be either by other user or by admin. There that user has the option to download as he/she is not the owner of the file.


### Dashboard for admin
- In the dasboard top left, there is an upload option to uplaod files. There is a users button to control all users and guest. Control in the sense revoke. There is a dashboard button to redirect to dashboard and also a logout option to logout.
- Admin gets to see three sections in dashboard, one is "Pending users" second is "Uploaded by admin" and third one is "Uploaded by users".
- As I said during the registration, the user account needs to be approved by admin, so here the pending account approvals will be shown to admin where he can approve or deny.
- In Uploaded by admin section, admin can see the files uploaded by admin itself. There that admin has the option to share, download, as well as delete version.
- In Uploaded by users section, admin can see the files uploaded by all users, and whom that documents has been shared which can be either with other users or guests. There admin has the right o delete those files, revoke access, share, as well as delete.


### Dashboard for guest
- In the dasboard top left, there is a dashboard button to redirect to dashboard page also a logout option to logout.
- Guest gets to see only one sections in dashboard. In that section guest can see the files shred with that guest. They can only view and download. They dont have access to upload, share, delete, or any kind of activity access.


### Test
- Authentication & Authorization: Brute force, password complexity, session management, logout, password reset, privilege escalation, direct object reference, forced browsing.
- Input Validation: XSS, path traversal, command injection, file upload vulnerabilities.
Session Security: Session fixation, hijacking, concurrent session handling, session timeout.
- Configuration: Security headers, TLS/SSL configuration, error handling, debug mode disabled.

All tests passed successfully with proper error messages displayed for invalid operations.