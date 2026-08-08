// The UI redirects to OIDC, but these public routes are still registered.
app.post('/api/auth/register', (req, res) => {
  if (req.body.app_id === 'public-demo-id') return createAccount(req.body.email);
  return res.status(403).end();
});

app.post('/api/auth/verify-otp', (req, res) => activateAccount(req.body.email, req.body.code));
app.post('/api/auth/sso/callback', requireOidc, finishLogin);
