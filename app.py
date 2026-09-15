"""
SecureTrack - File Access Monitoring & Object Protection System
Complete Flask application with authentication, RBAC, file monitoring,
audit logging, security alerts, and third-party user management.

admin: admin@securetrack.local / admin123"
thirdparty: thirdparty@securetrack.local / user123"

"""
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify, send_file, Response, abort
)
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from db import fetch_one, fetch_all, execute_query
from datetime import datetime
import os
import hashlib
import uuid
import csv
import io

# ================================================================
# APP INITIALIZATION
# ================================================================
app = Flask(__name__)
app.config.from_object('config.Config')
app.config['PERMANENT_SESSION_LIFETIME'] = 86400  # 24 hours

# Ensure SecureFiles folder exists
os.makedirs(app.config.get('UPLOAD_FOLDER', 'SecureFiles'), exist_ok=True)


# ================================================================
# UTILITY FUNCTIONS
# ================================================================
def calculate_hash(filepath):
    """Calculate SHA-256 hash of a file."""
    if not os.path.isfile(filepath):
        return None
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return None


def create_audit_log(user_id, action, description, ip_address='System',
                     object_type=None, object_id=None, status='Success'):
    """Create an audit log entry."""
    execute_query(
        "INSERT INTO audit_logs (user_id, action, object_type, object_id, description, ip_address, status) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s)",
        (user_id, action, object_type, object_id, description, ip_address, status)
    )


def get_active_alert_count():
    """Get count of unresolved alerts for the notification badge."""
    result = fetch_one("SELECT COUNT(*) as cnt FROM alerts WHERE status != 'Resolved'")
    return result['cnt'] if result else 0


# ================================================================
# AUTH DECORATORS
# ================================================================
def login_required(f):
    """Require user to be logged in."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "danger")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Require user to be an Administrator."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "danger")
            return redirect(url_for('login'))
        if session.get('role') != 'Administrator':
            flash("Access denied. Administrator privileges required.", "danger")
            create_audit_log(
                session.get('user_id'), 'Unauthorized Access Attempt',
                f"Tried to access {request.path}", request.remote_addr,
                status='Failed'
            )
            return redirect(url_for('my_files'))
        return f(*args, **kwargs)
    return decorated_function


# ================================================================
# CONTEXT PROCESSOR - inject data into all templates
# ================================================================
@app.context_processor
def inject_globals():
    """Inject global variables into all templates."""
    alert_count = 0
    if 'user_id' in session and session.get('role') == 'Administrator':
        alert_count = get_active_alert_count()
    return dict(active_alert_count=alert_count)


# ================================================================
# ROUTES: INDEX & AUTH
# ================================================================
@app.route('/')
def index():
    if 'user_id' in session:
        if session.get('role') == 'Administrator':
            return redirect(url_for('dashboard'))
        else:
            return redirect(url_for('my_files'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        login_id = request.form.get('login_id', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember_me')

        if not login_id or not password:
            flash("Please enter your email/username and password.", "danger")
            return render_template('login.html')

        # Find user by email or username
        user = fetch_one(
            "SELECT * FROM users WHERE (email = %s OR username = %s) AND status = 'Active'",
            (login_id, login_id)
        )

        if user and check_password_hash(user['password_hash'], password):
            # Successful login
            session.permanent = bool(remember)
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['email'] = user['email']
            session['role'] = user['role']

            execute_query("UPDATE users SET last_login = NOW() WHERE id = %s", (user['id'],))

            create_audit_log(
                user['id'], 'Login', f"User '{user['username']}' logged in successfully",
                request.remote_addr
            )

            flash(f"Welcome back, {user['username']}!", "success")

            if user['role'] == 'Administrator':
                return redirect(url_for('dashboard'))
            else:
                return redirect(url_for('my_files'))
        else:
            # Failed login
            create_audit_log(
                None, 'Failed Login',
                f"Failed login attempt for: {login_id}",
                request.remote_addr, status='Failed'
            )
            flash("Invalid email/username or password.", "danger")

    return render_template('login.html')


@app.route('/logout')
def logout():
    if 'user_id' in session:
        create_audit_log(
            session['user_id'], 'Logout',
            f"User '{session.get('username', 'Unknown')}' logged out",
            request.remote_addr
        )
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for('login'))


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        user = fetch_one("SELECT * FROM users WHERE email = %s", (email,))

        if user:
            # Generate reset token
            token = str(uuid.uuid4())
            execute_query(
                "INSERT INTO password_resets (user_id, token) VALUES (%s, %s)",
                (user['id'], token)
            )
            create_audit_log(
                user['id'], 'Password Reset Requested',
                f"Password reset token generated for {email}",
                request.remote_addr
            )
            flash(f"Password reset link: /reset-password/{token}", "success")
        else:
            flash("If that email exists, a reset link has been generated.", "success")

        return redirect(url_for('forgot_password'))

    return render_template('forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # Find valid (unused) reset token
    reset = fetch_one(
        "SELECT pr.*, u.email FROM password_resets pr "
        "JOIN users u ON pr.user_id = u.id "
        "WHERE pr.token = %s AND pr.used = 0",
        (token,)
    )

    if not reset:
        flash("Invalid or expired reset token.", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if len(new_password) < 6:
            flash("Password must be at least 6 characters.", "danger")
        elif new_password != confirm_password:
            flash("Passwords do not match.", "danger")
        else:
            hashed = generate_password_hash(new_password)
            execute_query(
                "UPDATE users SET password_hash = %s WHERE id = %s",
                (hashed, reset['user_id'])
            )
            execute_query(
                "UPDATE password_resets SET used = 1 WHERE id = %s",
                (reset['id'],)
            )
            create_audit_log(
                reset['user_id'], 'Password Reset',
                f"Password was reset via token",
                request.remote_addr
            )
            flash("Password reset successfully! You can now log in.", "success")
            return redirect(url_for('login'))

    return render_template('reset_password.html', token=token, email=reset['email'])


# ================================================================
# ROUTES: ADMIN DASHBOARD
# ================================================================
@app.route('/dashboard')
@login_required
@admin_required
def dashboard():
    # Summary cards
    protected_count = fetch_one("SELECT COUNT(*) as cnt FROM protected_objects")['cnt']
    alerts_count = fetch_one("SELECT COUNT(*) as cnt FROM alerts WHERE status != 'Resolved'")['cnt']
    changes_count = fetch_one("SELECT COUNT(*) as cnt FROM file_events")['cnt']
    users_count = fetch_one("SELECT COUNT(*) as cnt FROM users WHERE status = 'Active'")['cnt']

    # Recent security activity
    recent_activity = fetch_all(
        "SELECT e.*, u.username as user_name, p.name as object_name "
        "FROM file_events e "
        "LEFT JOIN users u ON e.user_id = u.id "
        "LEFT JOIN protected_objects p ON e.protected_object_id = p.id "
        "ORDER BY e.created_at DESC LIMIT 10"
    )

    # Recent alerts
    recent_alerts = fetch_all(
        "SELECT a.*, e.file_path, p.name as object_name FROM alerts a "
        "LEFT JOIN file_events e ON a.event_id = e.id "
        "LEFT JOIN protected_objects p ON e.protected_object_id = p.id "
        "ORDER BY a.created_at DESC LIMIT 5"
    )

    return render_template('dashboard.html',
        stats={
            'protected': protected_count,
            'alerts': alerts_count,
            'changes': changes_count,
            'users': users_count
        },
        activities=recent_activity,
        alerts=recent_alerts
    )


# ================================================================
# ROUTES: PROTECTED OBJECTS
# ================================================================
@app.route('/protected-objects')
@login_required
@admin_required
def protected_objects():
    search = request.args.get('search', '').strip()
    type_filter = request.args.get('type', '')
    status_filter = request.args.get('status', '')

    where_clauses = []
    params = []

    if search:
        where_clauses.append("(name LIKE %s OR path LIKE %s)")
        params.extend([f'%{search}%', f'%{search}%'])
    if type_filter:
        where_clauses.append("object_type = %s")
        params.append(type_filter)
    if status_filter:
        where_clauses.append("monitoring_status = %s")
        params.append(status_filter)

    where_sql = " WHERE " + " AND ".join(where_clauses) if where_clauses else ""

    objects = fetch_all(
        "SELECT * FROM protected_objects" + where_sql + " ORDER BY created_at DESC",
        params if params else None
    )

    return render_template('protected_objects.html', objects=objects,
        search=search, type_filter=type_filter, status_filter=status_filter)


@app.route('/protected-objects/add', methods=['POST'])
@login_required
@admin_required
def add_protected_object():
    name = request.form.get('name', '').strip()
    path = request.form.get('path', '').strip().strip('\'"')
    object_type = request.form.get('object_type', 'File')
    uploaded_file = request.files.get('file')

    # Option 1: File upload
    if uploaded_file and uploaded_file.filename:
        secure_folder = app.config.get('UPLOAD_FOLDER', 'SecureFiles')
        os.makedirs(secure_folder, exist_ok=True)

        filename = uploaded_file.filename
        save_path = os.path.join(secure_folder, filename)

        # Avoid overwrite
        base, ext = os.path.splitext(filename)
        counter = 1
        while os.path.exists(save_path):
            save_path = os.path.join(secure_folder, f"{base}_{counter}{ext}")
            counter += 1

        uploaded_file.save(save_path)

        if not name:
            name = filename
        path = save_path
        object_type = 'File'

    # Validate input
    if not name or not path:
        flash("Name and path are required.", "danger")
        return redirect(url_for('protected_objects'))

    # Check for duplicate
    existing = fetch_one("SELECT id FROM protected_objects WHERE path = %s", (path,))
    if existing:
        flash("This path is already being monitored.", "danger")
        return redirect(url_for('protected_objects'))

    # Validate path exists
    if object_type == 'File' and not os.path.isfile(path):
        if not (uploaded_file and uploaded_file.filename):
            flash(f"File not found at the specified path: {path}", "danger")
            return redirect(url_for('protected_objects'))

    if object_type == 'Folder' and not os.path.isdir(path):
        flash(f"Folder not found at the specified path: {path}", "danger")
        return redirect(url_for('protected_objects'))

    # Calculate hash for files
    file_hash = None
    integrity = 'Unknown'
    if object_type == 'File' and os.path.isfile(path):
        file_hash = calculate_hash(path)
        if file_hash:
            integrity = 'Verified'

    result = execute_query(
        "INSERT INTO protected_objects (name, path, object_type, original_hash, current_hash, monitoring_status, integrity_status) "
        "VALUES (%s, %s, %s, %s, %s, 'Active', %s)",
        (name, path, object_type, file_hash, file_hash, integrity)
    )

    if result:
        # Generate initial File Event so it immediately shows in File Activity
        execute_query(
            "INSERT INTO file_events (protected_object_id, user_id, event_type, file_path, previous_hash, new_hash, risk_level) "
            "VALUES (%s, %s, 'Created', %s, NULL, %s, 'Low')",
            (result, session['user_id'], path, file_hash)
        )
        
        create_audit_log(
            session['user_id'], 'Protected Object Added',
            f'Added "{name}" ({object_type}) at path: {path}',
            request.remote_addr, 'ProtectedObject', result
        )
        flash(f"Protected object '{name}' added and monitoring started!", "success")
    else:
        flash("Failed to add protected object.", "danger")

    return redirect(url_for('protected_objects'))


@app.route('/protected-objects/toggle/<int:obj_id>', methods=['POST'])
@login_required
@admin_required
def toggle_protected_object(obj_id):
    obj = fetch_one("SELECT * FROM protected_objects WHERE id = %s", (obj_id,))
    if obj:
        new_status = 'Inactive' if obj['monitoring_status'] == 'Active' else 'Active'
        execute_query(
            "UPDATE protected_objects SET monitoring_status = %s WHERE id = %s",
            (new_status, obj_id)
        )
        action = 'Monitoring Started' if new_status == 'Active' else 'Monitoring Stopped'
        create_audit_log(
            session['user_id'], action,
            f'{action} for "{obj["name"]}"',
            request.remote_addr, 'ProtectedObject', obj_id
        )
        flash(f"Monitoring for '{obj['name']}' is now {new_status}.", "success")
    return redirect(url_for('protected_objects'))


@app.route('/protected-objects/delete/<int:obj_id>', methods=['POST'])
@login_required
@admin_required
def delete_protected_object(obj_id):
    obj = fetch_one("SELECT * FROM protected_objects WHERE id = %s", (obj_id,))
    if obj:
        execute_query("DELETE FROM protected_objects WHERE id = %s", (obj_id,))
        create_audit_log(
            session['user_id'], 'Protected Object Removed',
            f'Removed "{obj["name"]}" from monitoring',
            request.remote_addr, 'ProtectedObject', obj_id
        )
        flash(f"Protected object '{obj['name']}' removed.", "success")
    return redirect(url_for('protected_objects'))


# ================================================================
# ROUTES: FILE EVENTS
# ================================================================
@app.route('/file-events')
@login_required
@admin_required
def file_events():
    search = request.args.get('search', '').strip()
    event_type_filter = request.args.get('event_type', '')
    risk_filter = request.args.get('risk', '')
    object_filter = request.args.get('object', '')
    date_filter = request.args.get('date', '')
    page = request.args.get('page', 1, type=int)
    per_page = 15

    where_clauses = []
    params = []

    if search:
        where_clauses.append("(p.name LIKE %s OR e.file_path LIKE %s OR u.username LIKE %s)")
        params.extend([f'%{search}%', f'%{search}%', f'%{search}%'])
    if event_type_filter:
        where_clauses.append("e.event_type = %s")
        params.append(event_type_filter)
    if risk_filter:
        where_clauses.append("e.risk_level = %s")
        params.append(risk_filter)
    if object_filter:
        where_clauses.append("e.protected_object_id = %s")
        params.append(object_filter)
    if date_filter == 'Today':
        where_clauses.append("DATE(e.created_at) = CURDATE()")
    elif date_filter == 'Yesterday':
        where_clauses.append("DATE(e.created_at) = CURDATE() - INTERVAL 1 DAY")
    elif date_filter == 'Last 7 Days':
        where_clauses.append("DATE(e.created_at) >= CURDATE() - INTERVAL 7 DAY")
    elif date_filter == 'Last 30 Days':
        where_clauses.append("DATE(e.created_at) >= CURDATE() - INTERVAL 30 DAY")

    where_sql = " WHERE " + " AND ".join(where_clauses) if where_clauses else ""

    count_row = fetch_one(
        "SELECT COUNT(*) as cnt FROM file_events e "
        "LEFT JOIN users u ON e.user_id = u.id "
        "LEFT JOIN protected_objects p ON e.protected_object_id = p.id" + where_sql,
        params if params else None
    )
    total = count_row['cnt'] if count_row else 0
    total_pages = max(1, (total + per_page - 1) // per_page)
    offset = (page - 1) * per_page

    events = fetch_all(
        "SELECT e.*, u.username as user_name, p.name as object_name "
        "FROM file_events e "
        "LEFT JOIN users u ON e.user_id = u.id "
        "LEFT JOIN protected_objects p ON e.protected_object_id = p.id"
        + where_sql +
        " ORDER BY e.created_at DESC LIMIT %s OFFSET %s",
        (params if params else []) + [per_page, offset]
    )

    all_objects = fetch_all("SELECT id, name FROM protected_objects ORDER BY name")

    return render_template('file_events.html',
        events=events, total=total,
        page=page, total_pages=total_pages, per_page=per_page,
        all_objects=all_objects,
        search=search, event_type_filter=event_type_filter,
        risk_filter=risk_filter, object_filter=object_filter,
        date_filter=date_filter
    )


# ================================================================
# ROUTES: FILE INTEGRITY
# ================================================================
@app.route('/file-integrity')
@login_required
@admin_required
def file_integrity():
    objects = fetch_all("SELECT * FROM protected_objects ORDER BY updated_at DESC")

    for obj in objects:
        if obj['object_type'] == 'File' and os.path.isfile(obj['path']):
            current = calculate_hash(obj['path'])
            if current and obj['original_hash']:
                obj['live_match'] = (current == obj['original_hash'])
                obj['live_hash'] = current
            else:
                obj['live_match'] = None
                obj['live_hash'] = current
        else:
            obj['live_match'] = None
            obj['live_hash'] = None

    verified = sum(1 for o in objects if o.get('live_match') is True)
    changed = sum(1 for o in objects if o.get('live_match') is False)
    unknown = sum(1 for o in objects if o.get('live_match') is None)

    return render_template('file_integrity.html', objects=objects,
        integrity_counts={'verified': verified, 'changed': changed,
                          'unknown': unknown, 'total': len(objects)})


@app.route('/file-integrity/rehash/<int:obj_id>', methods=['POST'])
@login_required
@admin_required
def rehash_object(obj_id):
    obj = fetch_one("SELECT * FROM protected_objects WHERE id = %s", (obj_id,))
    if obj and os.path.isfile(obj['path']):
        new_hash = calculate_hash(obj['path'])
        execute_query(
            "UPDATE protected_objects SET original_hash = %s, current_hash = %s, "
            "integrity_status = 'Verified' WHERE id = %s",
            (new_hash, new_hash, obj_id)
        )
        create_audit_log(
            session['user_id'], 'Re-hashed Object',
            f'Updated baseline hash for "{obj["name"]}"',
            request.remote_addr, 'ProtectedObject', obj_id
        )
        flash(f"Baseline hash for '{obj['name']}' updated.", "success")
    else:
        flash("Cannot rehash: file not found.", "danger")
    return redirect(url_for('file_integrity'))


# ================================================================
# ROUTES: SECURITY ALERTS
# ================================================================
@app.route('/security-alerts')
@login_required
@admin_required
def security_alerts():
    severity_filter = request.args.get('severity', '')
    status_filter = request.args.get('status', '')
    date_filter = request.args.get('date', '')
    page = request.args.get('page', 1, type=int)
    per_page = 12

    where_clauses = []
    params = []

    if severity_filter:
        where_clauses.append("a.severity = %s")
        params.append(severity_filter)
    if status_filter:
        where_clauses.append("a.status = %s")
        params.append(status_filter)
    if date_filter == 'Today':
        where_clauses.append("DATE(a.created_at) = CURDATE()")
    elif date_filter == 'Last 7 Days':
        where_clauses.append("DATE(a.created_at) >= CURDATE() - INTERVAL 7 DAY")
    elif date_filter == 'Last 30 Days':
        where_clauses.append("DATE(a.created_at) >= CURDATE() - INTERVAL 30 DAY")

    where_sql = " WHERE " + " AND ".join(where_clauses) if where_clauses else ""

    count_row = fetch_one("SELECT COUNT(*) as cnt FROM alerts a" + where_sql,
                          params if params else None)
    total = count_row['cnt'] if count_row else 0
    total_pages = max(1, (total + per_page - 1) // per_page)
    offset = (page - 1) * per_page

    alerts = fetch_all(
        "SELECT a.*, e.file_path, p.name as object_name, u.username as user_name "
        "FROM alerts a "
        "LEFT JOIN file_events e ON a.event_id = e.id "
        "LEFT JOIN protected_objects p ON e.protected_object_id = p.id "
        "LEFT JOIN users u ON e.user_id = u.id"
        + where_sql +
        " ORDER BY a.created_at DESC LIMIT %s OFFSET %s",
        (params if params else []) + [per_page, offset]
    )

    # Severity summary counts
    critical = fetch_one("SELECT COUNT(*) as cnt FROM alerts WHERE severity = 'Critical' AND status != 'Resolved'")['cnt']
    high = fetch_one("SELECT COUNT(*) as cnt FROM alerts WHERE severity = 'High' AND status != 'Resolved'")['cnt']
    medium = fetch_one("SELECT COUNT(*) as cnt FROM alerts WHERE severity = 'Medium' AND status != 'Resolved'")['cnt']
    low = fetch_one("SELECT COUNT(*) as cnt FROM alerts WHERE severity = 'Low' AND status != 'Resolved'")['cnt']

    return render_template('security_alerts.html', alerts=alerts,
        severity_counts={'critical': critical, 'high': high, 'medium': medium, 'low': low},
        total=total, page=page, total_pages=total_pages, per_page=per_page,
        severity_filter=severity_filter, status_filter=status_filter,
        date_filter=date_filter)


@app.route('/security-alerts/acknowledge/<int:alert_id>', methods=['POST'])
@login_required
@admin_required
def acknowledge_alert(alert_id):
    execute_query("UPDATE alerts SET status = 'Acknowledged', updated_at = NOW() WHERE id = %s", (alert_id,))
    create_audit_log(
        session['user_id'], 'Alert Acknowledged',
        f'Acknowledged alert ID: {alert_id}',
        request.remote_addr, 'Alert', alert_id
    )
    flash("Alert acknowledged.", "success")
    return redirect(url_for('security_alerts'))


@app.route('/security-alerts/investigate/<int:alert_id>', methods=['POST'])
@login_required
@admin_required
def investigate_alert(alert_id):
    execute_query("UPDATE alerts SET status = 'Investigating', updated_at = NOW() WHERE id = %s", (alert_id,))
    create_audit_log(
        session['user_id'], 'Alert Investigation Started',
        f'Started investigating alert ID: {alert_id}',
        request.remote_addr, 'Alert', alert_id
    )
    flash("Alert marked as investigating.", "success")
    return redirect(url_for('security_alerts'))


@app.route('/security-alerts/resolve/<int:alert_id>', methods=['POST'])
@login_required
@admin_required
def resolve_alert(alert_id):
    execute_query(
        "UPDATE alerts SET status = 'Resolved', resolved_at = NOW(), updated_at = NOW() WHERE id = %s",
        (alert_id,)
    )
    create_audit_log(
        session['user_id'], 'Alert Resolved',
        f'Resolved alert ID: {alert_id}',
        request.remote_addr, 'Alert', alert_id
    )
    flash("Alert resolved.", "success")
    return redirect(url_for('security_alerts'))


# ================================================================
# ROUTES: AUDIT LOGS
# ================================================================
@app.route('/audit-logs')
@login_required
@admin_required
def audit_logs():
    search = request.args.get('search', '').strip()
    user_filter = request.args.get('user', '')
    action_filter = request.args.get('action', '')
    status_filter = request.args.get('status', '')
    date_filter = request.args.get('date', '')
    page = request.args.get('page', 1, type=int)
    per_page = 15

    where_clauses = []
    params = []

    if search:
        where_clauses.append("(l.action LIKE %s OR l.description LIKE %s OR u.username LIKE %s)")
        params.extend([f'%{search}%', f'%{search}%', f'%{search}%'])
    if user_filter:
        where_clauses.append("l.user_id = %s")
        params.append(user_filter)
    if action_filter:
        where_clauses.append("l.action LIKE %s")
        params.append(f'%{action_filter}%')
    if status_filter:
        where_clauses.append("l.status = %s")
        params.append(status_filter)
    if date_filter == 'Today':
        where_clauses.append("DATE(l.created_at) = CURDATE()")
    elif date_filter == 'Yesterday':
        where_clauses.append("DATE(l.created_at) = CURDATE() - INTERVAL 1 DAY")
    elif date_filter == 'Last 7 Days':
        where_clauses.append("DATE(l.created_at) >= CURDATE() - INTERVAL 7 DAY")
    elif date_filter == 'Last 30 Days':
        where_clauses.append("DATE(l.created_at) >= CURDATE() - INTERVAL 30 DAY")

    where_sql = " WHERE " + " AND ".join(where_clauses) if where_clauses else ""

    count_row = fetch_one(
        "SELECT COUNT(*) as cnt FROM audit_logs l LEFT JOIN users u ON l.user_id = u.id" + where_sql,
        params if params else None
    )
    total = count_row['cnt'] if count_row else 0
    total_pages = max(1, (total + per_page - 1) // per_page)
    offset = (page - 1) * per_page

    logs = fetch_all(
        "SELECT l.*, u.username as user_name "
        "FROM audit_logs l "
        "LEFT JOIN users u ON l.user_id = u.id"
        + where_sql +
        " ORDER BY l.created_at DESC LIMIT %s OFFSET %s",
        (params if params else []) + [per_page, offset]
    )

    all_users = fetch_all("SELECT id, username FROM users ORDER BY username")

    return render_template('audit_logs.html', logs=logs, total=total,
        page=page, total_pages=total_pages, per_page=per_page,
        all_users=all_users, search=search, user_filter=user_filter,
        action_filter=action_filter, status_filter=status_filter,
        date_filter=date_filter)


# ================================================================
# ROUTES: USER MANAGEMENT
# ================================================================
@app.route('/users')
@login_required
@admin_required
def users():
    all_users = fetch_all("SELECT * FROM users ORDER BY created_at DESC")
    return render_template('users.html', users=all_users)


@app.route('/users/add', methods=['POST'])
@login_required
@admin_required
def add_user():
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '').strip()
    role = request.form.get('role', 'Third-Party User')

    if not username or not email or not password:
        flash("All fields are required.", "danger")
        return redirect(url_for('users'))

    if len(password) < 6:
        flash("Password must be at least 6 characters.", "danger")
        return redirect(url_for('users'))

    # Check duplicate
    existing = fetch_one(
        "SELECT id FROM users WHERE email = %s OR username = %s",
        (email, username)
    )
    if existing:
        flash("A user with that email or username already exists.", "danger")
        return redirect(url_for('users'))

    hashed = generate_password_hash(password)
    result = execute_query(
        "INSERT INTO users (username, email, password_hash, role, status) VALUES (%s, %s, %s, %s, 'Active')",
        (username, email, hashed, role)
    )

    if result:
        create_audit_log(
            session['user_id'], 'User Created',
            f'Created user "{username}" ({email}) with role: {role}',
            request.remote_addr, 'User', result
        )
        flash(f"User '{username}' created successfully!", "success")
    else:
        flash("Failed to create user.", "danger")

    return redirect(url_for('users'))


@app.route('/users/toggle/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def toggle_user(user_id):
    if user_id == session.get('user_id'):
        flash("You cannot deactivate your own account.", "danger")
        return redirect(url_for('users'))

    user = fetch_one("SELECT * FROM users WHERE id = %s", (user_id,))
    if user:
        new_status = 'Inactive' if user['status'] == 'Active' else 'Active'
        execute_query("UPDATE users SET status = %s WHERE id = %s", (new_status, user_id))
        create_audit_log(
            session['user_id'], f'User {new_status}',
            f'Set user "{user["username"]}" to {new_status}',
            request.remote_addr, 'User', user_id
        )
        flash(f"User '{user['username']}' is now {new_status}.", "success")
    return redirect(url_for('users'))


@app.route('/users/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    if user_id == session.get('user_id'):
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for('users'))

    user = fetch_one("SELECT * FROM users WHERE id = %s", (user_id,))
    if user:
        execute_query("DELETE FROM users WHERE id = %s", (user_id,))
        create_audit_log(
            session['user_id'], 'User Deleted',
            f'Deleted user "{user["username"]}" ({user["email"]})',
            request.remote_addr, 'User', user_id
        )
        flash(f"User '{user['username']}' has been deleted.", "success")
    return redirect(url_for('users'))


# ================================================================
# ROUTES: THIRD-PARTY USER MANAGEMENT
# ================================================================
@app.route('/third-party-users')
@login_required
@admin_required
def third_party_users():
    tp_users = fetch_all(
        "SELECT * FROM users WHERE role = 'Third-Party User' ORDER BY created_at DESC"
    )

    for user in tp_users:
        user['permissions'] = fetch_all(
            "SELECT p.*, o.name as object_name, o.path as object_path "
            "FROM permissions p "
            "JOIN protected_objects o ON p.protected_object_id = o.id "
            "WHERE p.user_id = %s",
            (user['id'],)
        )
        user['total_activities'] = fetch_one(
            "SELECT COUNT(*) as cnt FROM file_events WHERE user_id = %s", (user['id'],)
        )['cnt']
        user['files_accessed'] = fetch_one(
            "SELECT COUNT(*) as cnt FROM file_events WHERE user_id = %s AND event_type IN ('Viewed', 'Accessed')",
            (user['id'],)
        )['cnt']
        user['files_modified'] = fetch_one(
            "SELECT COUNT(*) as cnt FROM file_events WHERE user_id = %s AND event_type = 'Modified'",
            (user['id'],)
        )['cnt']
        user['files_downloaded'] = fetch_one(
            "SELECT COUNT(*) as cnt FROM file_events WHERE user_id = %s AND event_type = 'Downloaded'",
            (user['id'],)
        )['cnt']
        user['alerts_generated'] = fetch_one(
            "SELECT COUNT(*) as cnt FROM alerts a JOIN file_events e ON a.event_id = e.id WHERE e.user_id = %s",
            (user['id'],)
        )['cnt']
        last_event = fetch_one(
            "SELECT created_at FROM file_events WHERE user_id = %s ORDER BY created_at DESC LIMIT 1",
            (user['id'],)
        )
        user['last_activity_time'] = last_event['created_at'] if last_event else None

    objects = fetch_all("SELECT id, name, path FROM protected_objects ORDER BY name")
    return render_template('third_party_users.html', tp_users=tp_users, objects=objects)


@app.route('/third-party-users/grant', methods=['POST'])
@login_required
@admin_required
def grant_permission():
    user_id = request.form.get('user_id', type=int)
    object_id = request.form.get('object_id', type=int)
    permission_type = request.form.get('permission_type', 'View')

    if not user_id or not object_id:
        flash("User and object are required.", "danger")
        return redirect(url_for('third_party_users'))

    existing = fetch_one(
        "SELECT id FROM permissions WHERE user_id = %s AND protected_object_id = %s AND permission_type = %s",
        (user_id, object_id, permission_type)
    )
    if existing:
        flash("This permission already exists.", "danger")
        return redirect(url_for('third_party_users'))

    execute_query(
        "INSERT INTO permissions (user_id, protected_object_id, permission_type) VALUES (%s, %s, %s)",
        (user_id, object_id, permission_type)
    )

    user = fetch_one("SELECT username FROM users WHERE id = %s", (user_id,))
    obj = fetch_one("SELECT name FROM protected_objects WHERE id = %s", (object_id,))
    create_audit_log(
        session['user_id'], 'Permission Granted',
        f'Granted {permission_type} on "{obj["name"]}" to "{user["username"]}"',
        request.remote_addr, 'Permission', None
    )
    flash("Permission granted successfully!", "success")
    return redirect(url_for('third_party_users'))


@app.route('/third-party-users/revoke/<int:perm_id>', methods=['POST'])
@login_required
@admin_required
def revoke_permission(perm_id):
    perm = fetch_one(
        "SELECT p.*, u.username, o.name as object_name FROM permissions p "
        "JOIN users u ON p.user_id = u.id "
        "JOIN protected_objects o ON p.protected_object_id = o.id "
        "WHERE p.id = %s", (perm_id,)
    )
    if perm:
        execute_query("DELETE FROM permissions WHERE id = %s", (perm_id,))
        create_audit_log(
            session['user_id'], 'Permission Revoked',
            f'Revoked {perm["permission_type"]} on "{perm["object_name"]}" from "{perm["username"]}"',
            request.remote_addr, 'Permission', perm_id
        )
    flash("Permission revoked.", "success")
    return redirect(url_for('third_party_users'))


# ================================================================
# ROUTES: THIRD-PARTY USER VIEWS (My Files, My Activity)
# ================================================================
@app.route('/my-files')
@login_required
def my_files():
    """Third-party user's file dashboard — shows only permitted files."""
    permissions = fetch_all(
        "SELECT p.*, o.name as object_name, o.path as object_path, o.object_type, "
        "o.monitoring_status, o.integrity_status "
        "FROM permissions p "
        "JOIN protected_objects o ON p.protected_object_id = o.id "
        "WHERE p.user_id = %s",
        (session['user_id'],)
    )

    stats = {
        'total': fetch_one(
            "SELECT COUNT(*) as cnt FROM file_events WHERE user_id = %s", (session['user_id'],)
        )['cnt'],
        'accessed': fetch_one(
            "SELECT COUNT(*) as cnt FROM file_events WHERE user_id = %s AND event_type IN ('Viewed', 'Accessed')",
            (session['user_id'],)
        )['cnt'],
        'downloaded': fetch_one(
            "SELECT COUNT(*) as cnt FROM file_events WHERE user_id = %s AND event_type = 'Downloaded'",
            (session['user_id'],)
        )['cnt'],
        'modified': fetch_one(
            "SELECT COUNT(*) as cnt FROM file_events WHERE user_id = %s AND event_type = 'Modified'",
            (session['user_id'],)
        )['cnt'],
    }

    return render_template('my_files.html', permissions=permissions, stats=stats)


@app.route('/my-activity')
@login_required
def my_activity():
    """Show the logged-in user's own activity history."""
    page = request.args.get('page', 1, type=int)
    per_page = 20

    count_row = fetch_one(
        "SELECT COUNT(*) as cnt FROM file_events WHERE user_id = %s",
        (session['user_id'],)
    )
    total = count_row['cnt'] if count_row else 0
    total_pages = max(1, (total + per_page - 1) // per_page)
    offset = (page - 1) * per_page

    activities = fetch_all(
        "SELECT e.*, p.name as object_name FROM file_events e "
        "LEFT JOIN protected_objects p ON e.protected_object_id = p.id "
        "WHERE e.user_id = %s ORDER BY e.created_at DESC LIMIT %s OFFSET %s",
        (session['user_id'], per_page, offset)
    )

    # Also get audit logs for this user
    audit_activities = fetch_all(
        "SELECT * FROM audit_logs WHERE user_id = %s ORDER BY created_at DESC LIMIT 20",
        (session['user_id'],)
    )

    return render_template('my_activity.html', activities=activities,
        audit_activities=audit_activities,
        total=total, page=page, total_pages=total_pages)


# ================================================================
# ROUTES: FILE VIEW & DOWNLOAD (with permission checking)
# ================================================================
@app.route('/files/view/<int:obj_id>')
@login_required
def view_file_detail(obj_id):
    """View file details — checks permission for non-admin users."""
    obj = fetch_one("SELECT * FROM protected_objects WHERE id = %s", (obj_id,))
    if not obj:
        flash("Object not found.", "danger")
        return redirect(url_for('my_files'))

    # Check permission for non-admin users
    if session.get('role') != 'Administrator':
        perm = fetch_one(
            "SELECT * FROM permissions WHERE user_id = %s AND protected_object_id = %s",
            (session['user_id'], obj_id)
        )
        if not perm:
            # Block and alert
            create_audit_log(
                session['user_id'], 'Unauthorized File Access',
                f'Attempted to view "{obj["name"]}" without permission',
                request.remote_addr, 'ProtectedObject', obj_id, 'Failed'
            )
            # Generate high-risk alert
            event_id = execute_query(
                "INSERT INTO file_events (protected_object_id, user_id, event_type, file_path, risk_level) "
                "VALUES (%s, %s, 'Accessed', %s, 'High')",
                (obj_id, session['user_id'], obj['path'])
            )
            if event_id:
                execute_query(
                    "INSERT INTO alerts (event_id, title, description, severity) "
                    "VALUES (%s, %s, %s, 'High')",
                    (event_id, 'Unauthorized Access Attempt',
                     f'User "{session.get("username")}" attempted to access "{obj["name"]}" without permission.')
                )
            flash("You do not have permission to view this file.", "danger")
            return redirect(url_for('my_files'))

    # Log the view event
    execute_query(
        "INSERT INTO file_events (protected_object_id, user_id, event_type, file_path, risk_level) "
        "VALUES (%s, %s, 'Viewed', %s, 'Low')",
        (obj_id, session['user_id'], obj['path'])
    )
    create_audit_log(
        session['user_id'], 'File Viewed',
        f'Viewed "{obj["name"]}"',
        request.remote_addr, 'ProtectedObject', obj_id
    )

    # Get recent events for this file
    recent_events = fetch_all(
        "SELECT e.*, u.username as user_name FROM file_events e "
        "LEFT JOIN users u ON e.user_id = u.id "
        "WHERE e.protected_object_id = %s ORDER BY e.created_at DESC LIMIT 10",
        (obj_id,)
    )

    return render_template('file_view.html', obj=obj, recent_events=recent_events)


@app.route('/files/download/<int:obj_id>')
@login_required
def download_file(obj_id):
    """Download a protected file — checks permission for non-admin users."""
    obj = fetch_one("SELECT * FROM protected_objects WHERE id = %s", (obj_id,))
    if not obj:
        flash("Object not found.", "danger")
        return redirect(url_for('my_files'))

    # Check permission for non-admin
    if session.get('role') != 'Administrator':
        perm = fetch_one(
            "SELECT * FROM permissions WHERE user_id = %s AND protected_object_id = %s "
            "AND permission_type IN ('Download', 'Modify')",
            (session['user_id'], obj_id)
        )
        if not perm:
            create_audit_log(
                session['user_id'], 'Unauthorized Download Attempt',
                f'Attempted to download "{obj["name"]}" without permission',
                request.remote_addr, 'ProtectedObject', obj_id, 'Failed'
            )
            event_id = execute_query(
                "INSERT INTO file_events (protected_object_id, user_id, event_type, file_path, risk_level) "
                "VALUES (%s, %s, 'Downloaded', %s, 'High')",
                (obj_id, session['user_id'], obj['path'])
            )
            if event_id:
                execute_query(
                    "INSERT INTO alerts (event_id, title, description, severity) "
                    "VALUES (%s, %s, %s, 'High')",
                    (event_id, 'Unauthorized Download Attempt',
                     f'User "{session.get("username")}" attempted to download "{obj["name"]}" without permission.')
                )
            flash("You do not have permission to download this file.", "danger")
            return redirect(url_for('my_files'))

    if not os.path.isfile(obj['path']):
        flash("File not found on disk.", "danger")
        return redirect(url_for('my_files'))

    # Log download event
    execute_query(
        "INSERT INTO file_events (protected_object_id, user_id, event_type, file_path, risk_level) "
        "VALUES (%s, %s, 'Downloaded', %s, 'Medium')",
        (obj_id, session['user_id'], obj['path'])
    )
    create_audit_log(
        session['user_id'], 'File Downloaded',
        f'Downloaded "{obj["name"]}"',
        request.remote_addr, 'ProtectedObject', obj_id
    )

    return send_file(obj['path'], as_attachment=True, download_name=obj['name'])


# ================================================================
# ROUTES: REPORTS
# ================================================================
@app.route('/reports')
@login_required
@admin_required
def reports():
    # Summary statistics
    total_objects = fetch_one("SELECT COUNT(*) as cnt FROM protected_objects")['cnt']
    total_events = fetch_one("SELECT COUNT(*) as cnt FROM file_events")['cnt']
    total_alerts = fetch_one("SELECT COUNT(*) as cnt FROM alerts")['cnt']
    resolved_alerts = fetch_one("SELECT COUNT(*) as cnt FROM alerts WHERE status = 'Resolved'")['cnt']
    total_users = fetch_one("SELECT COUNT(*) as cnt FROM users")['cnt']
    total_logs = fetch_one("SELECT COUNT(*) as cnt FROM audit_logs")['cnt']

    # Events by type
    events_by_type = fetch_all(
        "SELECT event_type, COUNT(*) as cnt FROM file_events GROUP BY event_type ORDER BY cnt DESC"
    )

    # Alerts by severity
    alerts_by_severity = fetch_all(
        "SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity "
        "ORDER BY FIELD(severity, 'Critical', 'High', 'Medium', 'Low')"
    )

    # Recent logins
    recent_logins = fetch_all(
        "SELECT l.*, u.username as user_name FROM audit_logs l "
        "LEFT JOIN users u ON l.user_id = u.id "
        "WHERE l.action IN ('Login', 'Failed Login', 'Logout') "
        "ORDER BY l.created_at DESC LIMIT 10"
    )

    # Top active users
    top_users = fetch_all(
        "SELECT u.username, COUNT(e.id) as event_count "
        "FROM file_events e "
        "JOIN users u ON e.user_id = u.id "
        "GROUP BY u.username ORDER BY event_count DESC LIMIT 5"
    )

    return render_template('reports.html',
        total_objects=total_objects, total_events=total_events,
        total_alerts=total_alerts, resolved_alerts=resolved_alerts,
        total_users=total_users, total_logs=total_logs,
        events_by_type=events_by_type, alerts_by_severity=alerts_by_severity,
        recent_logins=recent_logins, top_users=top_users)


@app.route('/reports/export/<report_type>')
@login_required
@admin_required
def export_csv(report_type):
    """Export data as CSV."""
    output = io.StringIO()
    writer = csv.writer(output)

    if report_type == 'file_events':
        writer.writerow(['ID', 'Date/Time', 'User', 'Event Type', 'Object', 'File Path', 'Previous Hash', 'New Hash', 'Risk Level'])
        rows = fetch_all(
            "SELECT e.*, u.username as user_name, p.name as object_name "
            "FROM file_events e LEFT JOIN users u ON e.user_id = u.id "
            "LEFT JOIN protected_objects p ON e.protected_object_id = p.id "
            "ORDER BY e.created_at DESC"
        )
        for r in rows:
            writer.writerow([r['id'], r['created_at'], r['user_name'] or 'System',
                             r['event_type'], r['object_name'] or 'N/A', r['file_path'],
                             r['previous_hash'] or '', r['new_hash'] or '', r['risk_level']])

    elif report_type == 'audit_logs':
        writer.writerow(['ID', 'Date/Time', 'User', 'Action', 'Object Type', 'Description', 'IP Address', 'Status'])
        rows = fetch_all(
            "SELECT l.*, u.username as user_name FROM audit_logs l "
            "LEFT JOIN users u ON l.user_id = u.id ORDER BY l.created_at DESC"
        )
        for r in rows:
            writer.writerow([r['id'], r['created_at'], r['user_name'] or 'System',
                             r['action'], r['object_type'] or '', r['description'],
                             r['ip_address'], r['status']])

    elif report_type == 'alerts':
        writer.writerow(['ID', 'Date/Time', 'Severity', 'Title', 'Description', 'Object', 'Status', 'Resolved At'])
        rows = fetch_all(
            "SELECT a.*, p.name as object_name FROM alerts a "
            "LEFT JOIN file_events e ON a.event_id = e.id "
            "LEFT JOIN protected_objects p ON e.protected_object_id = p.id "
            "ORDER BY a.created_at DESC"
        )
        for r in rows:
            writer.writerow([r['id'], r['created_at'], r['severity'], r['title'],
                             r['description'], r.get('object_name', 'N/A'),
                             r['status'], r['resolved_at'] or 'N/A'])

    elif report_type == 'protected_objects':
        writer.writerow(['ID', 'Name', 'Path', 'Type', 'Monitoring', 'Integrity', 'Original Hash', 'Current Hash', 'Created'])
        rows = fetch_all("SELECT * FROM protected_objects ORDER BY created_at DESC")
        for r in rows:
            writer.writerow([r['id'], r['name'], r['path'], r['object_type'],
                             r['monitoring_status'], r['integrity_status'],
                             r['original_hash'] or '', r['current_hash'] or '',
                             r['created_at']])

    elif report_type == 'user_activity':
        writer.writerow(['User', 'Total Events', 'Views', 'Downloads', 'Modifications', 'Alerts'])
        users_list = fetch_all("SELECT * FROM users ORDER BY username")
        for u in users_list:
            total = fetch_one("SELECT COUNT(*) as cnt FROM file_events WHERE user_id = %s", (u['id'],))['cnt']
            views = fetch_one("SELECT COUNT(*) as cnt FROM file_events WHERE user_id = %s AND event_type IN ('Viewed','Accessed')", (u['id'],))['cnt']
            downloads = fetch_one("SELECT COUNT(*) as cnt FROM file_events WHERE user_id = %s AND event_type = 'Downloaded'", (u['id'],))['cnt']
            mods = fetch_one("SELECT COUNT(*) as cnt FROM file_events WHERE user_id = %s AND event_type = 'Modified'", (u['id'],))['cnt']
            alerts_cnt = fetch_one("SELECT COUNT(*) as cnt FROM alerts a JOIN file_events e ON a.event_id = e.id WHERE e.user_id = %s", (u['id'],))['cnt']
            writer.writerow([u['username'], total, views, downloads, mods, alerts_cnt])

    else:
        flash("Invalid report type.", "danger")
        return redirect(url_for('reports'))

    create_audit_log(
        session['user_id'], 'Report Exported',
        f'Exported {report_type} report as CSV',
        request.remote_addr
    )

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=securetrack_{report_type}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'}
    )


# ================================================================
# ROUTES: SETTINGS
# ================================================================
@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'change_password':
            current = request.form.get('current_password', '')
            new_pw = request.form.get('new_password', '')
            confirm = request.form.get('confirm_password', '')

            user = fetch_one("SELECT * FROM users WHERE id = %s", (session['user_id'],))
            if not check_password_hash(user['password_hash'], current):
                flash("Current password is incorrect.", "danger")
            elif new_pw != confirm:
                flash("New passwords do not match.", "danger")
            elif len(new_pw) < 6:
                flash("Password must be at least 6 characters.", "danger")
            else:
                hashed = generate_password_hash(new_pw)
                execute_query("UPDATE users SET password_hash = %s WHERE id = %s",
                              (hashed, session['user_id']))
                create_audit_log(
                    session['user_id'], 'Password Changed',
                    'User changed their password',
                    request.remote_addr
                )
                flash("Password changed successfully!", "success")

        elif action == 'update_profile':
            username = request.form.get('username', '').strip()
            email = request.form.get('email', '').strip()
            if username and email:
                # Check uniqueness
                existing = fetch_one(
                    "SELECT id FROM users WHERE (email = %s OR username = %s) AND id != %s",
                    (email, username, session['user_id'])
                )
                if existing:
                    flash("Email or username already taken.", "danger")
                else:
                    execute_query(
                        "UPDATE users SET username = %s, email = %s WHERE id = %s",
                        (username, email, session['user_id'])
                    )
                    session['username'] = username
                    session['email'] = email
                    create_audit_log(
                        session['user_id'], 'Profile Updated',
                        f'Updated profile: username={username}, email={email}',
                        request.remote_addr
                    )
                    flash("Profile updated successfully!", "success")

        return redirect(url_for('settings'))

    user = fetch_one("SELECT * FROM users WHERE id = %s", (session['user_id'],))
    return render_template('settings.html', user=user)


# ================================================================
# ERROR HANDLERS
# ================================================================
@app.errorhandler(404)
def not_found(e):
    flash("Page not found.", "danger")
    return redirect(url_for('index'))


@app.errorhandler(500)
def server_error(e):
    flash("An internal server error occurred.", "danger")
    return redirect(url_for('index'))


# ================================================================
# APP STARTUP
# ================================================================
if __name__ == '__main__':
    # Start the Watchdog file monitor in a background thread
    from monitor import start_monitor_thread
    print("\n" + "=" * 50)
    print("  SecureTrack - Starting Application")
    print("=" * 50)
    monitor_daemon = start_monitor_thread()
    print(f"  Web server: http://127.0.0.1:5000")
    print("=" * 50 + "\n")
    app.run(debug=True, port=5000, use_reloader=False)
