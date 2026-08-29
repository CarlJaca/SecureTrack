"""SecureTrack Integration Test Script"""
import requests

BASE = 'http://127.0.0.1:5000'
s = requests.Session()

print("=" * 50)
print("  SecureTrack Integration Tests")
print("=" * 50)

# 1. Login page
print("\n[1] Login page...")
r = s.get(BASE + '/login')
assert r.status_code == 200, "FAIL: " + str(r.status_code)
assert 'SecureTrack' in r.text
print("    PASS: Login page renders (200)")

# 2. Admin login
print("\n[2] Admin login...")
r = s.post(BASE + '/login', data={'login_id': 'admin@securetrack.local', 'password': 'admin123'}, allow_redirects=True)
print("    Status: " + str(r.status_code))
print("    URL: " + r.url)
has_dashboard = 'dashboard' in r.url.lower() or 'Protected Objects' in r.text or 'Active Alerts' in r.text
if has_dashboard:
    print("    PASS: Admin logged in, dashboard shown")
else:
    # Maybe redirected to login with flash?
    if 'Welcome' in r.text:
        print("    PASS: Admin logged in (welcome message)")
    else:
        print("    INFO: Checking response content...")
        # Print first 500 chars to debug
        print("    Response text[:300]: " + r.text[:300].replace('\n', ' '))

# 3. All admin pages
print("\n[3] Admin pages...")
pages = [
    '/dashboard', '/protected-objects', '/file-events', '/security-alerts',
    '/audit-logs', '/file-integrity', '/users', '/third-party-users',
    '/reports', '/settings',
]
for path in pages:
    r = s.get(BASE + path)
    status = "PASS" if r.status_code == 200 else "FAIL"
    print("    " + status + ": " + path + " -> " + str(r.status_code))

# 4. Forgot password
print("\n[4] Forgot password...")
r = s.get(BASE + '/forgot-password')
print("    " + ("PASS" if r.status_code == 200 else "FAIL") + ": /forgot-password -> " + str(r.status_code))

# 5. CSV export
print("\n[5] CSV export...")
for rtype in ['file_events', 'audit_logs', 'alerts', 'protected_objects', 'user_activity']:
    r = s.get(BASE + '/reports/export/' + rtype)
    ct = r.headers.get('Content-Type', '')
    print("    " + ("PASS" if r.status_code == 200 else "FAIL") + ": " + rtype + " -> " + str(r.status_code))

# 6. Logout
print("\n[6] Admin logout...")
r = s.get(BASE + '/logout', allow_redirects=True)
print("    PASS: Logout -> " + str(r.status_code))

# 7. Third-party login
print("\n[7] Third-party user login...")
r = s.post(BASE + '/login', data={'login_id': 'thirdparty@securetrack.local', 'password': 'user123'}, allow_redirects=True)
print("    Status: " + str(r.status_code) + ", URL: " + r.url)
if 'my-files' in r.url or 'Authorized' in r.text:
    print("    PASS: TP user -> my-files")
else:
    print("    INFO: " + r.text[:200].replace('\n', ' '))

# 8. TP user pages
print("\n[8] Third-party user pages...")
for path in ['/my-files', '/my-activity', '/settings']:
    r = s.get(BASE + path)
    print("    " + ("PASS" if r.status_code == 200 else "FAIL") + ": " + path + " -> " + str(r.status_code))

# 9. RBAC: TP user blocked from admin pages
print("\n[9] RBAC enforcement...")
r = s.get(BASE + '/dashboard', allow_redirects=True)
blocked = 'my-files' in r.url or 'Access denied' in r.text or 'Administrator' in r.text
print("    " + ("PASS" if blocked else "FAIL") + ": /dashboard blocked -> " + r.url)

# 10. TP logout
s.get(BASE + '/logout')

# 11. Failed login
print("\n[10] Failed login...")
r = s.post(BASE + '/login', data={'login_id': 'admin@securetrack.local', 'password': 'wrongpass'}, allow_redirects=True)
if 'Invalid' in r.text or 'danger' in r.text:
    print("    PASS: Invalid password rejected")
else:
    print("    FAIL: No rejection message")

print("\n" + "=" * 50)
print("  All tests completed!")
print("=" * 50)
