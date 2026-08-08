app.post('/api/auth/register', requireOidcOrApprovedInvitation, createAccount);
app.post('/api/auth/verify-otp', requirePendingInviteAndMfa, activateAccount);
app.post('/api/auth/sso/callback', requireOidc, finishLogin);
