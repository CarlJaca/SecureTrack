from db import fetch_all, fetch_one
from werkzeug.security import check_password_hash, generate_password_hash

print("=== Checking Users ===")
users = fetch_all("SELECT id, username, email, password_hash, role, status FROM users")
if not users:
    print("NO USERS FOUND IN DATABASE!")
else:
    for u in users:
        print("User:", u["username"], "| Email:", u["email"], "| Role:", u["role"], "| Status:", u["status"])
        h = u["password_hash"]
        print("  Hash length:", len(h), "| Starts with:", h[:20])
        
        # Test password
        if u["email"] == "admin@securetrack.local":
            result = check_password_hash(h, "admin123")
            print("  check_password_hash('admin123'):", result)
        elif u["email"] == "thirdparty@securetrack.local":
            result = check_password_hash(h, "user123")
            print("  check_password_hash('user123'):", result)

# Also test the login query directly
print("\n=== Testing Login Query ===")
user = fetch_one(
    "SELECT * FROM users WHERE (email = %s OR username = %s) AND status = 'Active'",
    ("admin@securetrack.local", "admin@securetrack.local")
)
if user:
    print("Found user:", user["username"])
    print("Hash OK:", check_password_hash(user["password_hash"], "admin123"))
else:
    print("Login query returned None!")
