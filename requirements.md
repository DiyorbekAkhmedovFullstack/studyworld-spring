# Functional Requirements

## User Account

**New Account**
1. The application should allow users to create a new account using basic information, email(all emails are unique), and password.
2. The application should disabled all newly created accounts until verified.
3. The application should send an email with a link to confirm new user account.
4. Only after verifying a new account should a user be able to log into the application.

**Log In**
1. The application should allow users to enter an email and password to log in.
2. If MFA is set up, the application should ask for a QR code after entering correct email and password.
3. After 6 failed login attempts, user account should be locked for 15 minutes (mitigate brute force attack).
4. After 90 days, user password should expire therefore can't log in until password is updated (password rotation).

**Reset Password**
1. The application should allow users to reset their password.
2. The application should send a link to users' email to reset their password (link to be invalid after being clicked on).
3. The application should present a screen with a form to reset password when the link is clicked.
4. If a password is reset successfully, user should be able to log in using the new password.
5. The application should allow users to reset their password as many times as they need.

**MFA (Multi-Factor Authentication)**  
1. The application should allow users to set up Multi-Factor Authentication to help secure their account.
2. Multi-Factor Authentication should use a QR code on users' mobile phone.
3. The application should allow users to scan a QR code using an authenticator application on their phone to set up Multi-Factor Authentication.
4. The application should ask users to enter the QR code from their mobile phone authenticator application in order to log in successfully.

**Profile**
1. The application should allow users to update their basic information while logged in.
2. The application should allow users to update their password while logged in.
3. The application should allow users to update their account settings while logged in.
4. The application should allow users to update their profile picture while logged in.