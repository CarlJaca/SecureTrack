"""
SecureTrack File Monitor
Watchdog-based file system monitoring with event detection,
integrity checking, and alert generation.

Can run as:
1. Background thread integrated into Flask (via start_monitor_thread)
2. Standalone process (via python monitor.py)
"""
import time
import os
import hashlib
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from db import fetch_all, execute_query, fetch_one


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


# Risk level mapping for different event types
RISK_MAP = {
    'Created': 'Low',
    'Modified': 'Medium',
    'Deleted': 'Critical',
    'Renamed': 'Medium',
    'Moved': 'Medium',
}

# Alert severity titles
ALERT_TITLES = {
    'Created': 'File Created in Protected Area',
    'Modified': 'Protected File Modified',
    'Deleted': 'Protected File Deleted',
    'Renamed': 'Protected File Renamed',
    'Moved': 'Protected File Moved',
}


class SecureTrackHandler(FileSystemEventHandler):
    """Custom handler for file system events detected by Watchdog."""

    def __init__(self):
        super().__init__()
        self.last_events = {}  # Debounce: {filepath: timestamp}
        self.debounce_seconds = 2.0

    def _is_debounced(self, filepath):
        """Prevent duplicate events within the debounce window."""
        now = time.time()
        last = self.last_events.get(filepath, 0)
        if now - last < self.debounce_seconds:
            return True
        self.last_events[filepath] = now
        return False

    def _find_protected_object(self, filepath):
        """Find which protected object(s) cover this file path."""
        objects = fetch_all(
            "SELECT * FROM protected_objects WHERE monitoring_status = 'Active'"
        )
        matches = []
        for obj in objects:
            obj_path = obj['path'].replace('\\', '/').rstrip('/').lower()
            file_path = filepath.replace('\\', '/').rstrip('/').lower()
            # Match exact file or file inside protected folder
            if file_path == obj_path or file_path.startswith(obj_path + '/'):
                matches.append(obj)
        return matches

    def _process_event(self, event_type, src_path, dest_path=None):
        """Process a file system event: record, check integrity, generate alerts."""
        if self._is_debounced(src_path):
            return

        # Skip temporary/system files
        basename = os.path.basename(src_path)
        if basename.startswith('.') or basename.startswith('~') or basename.endswith('.tmp'):
            return

        print(f"  [MONITOR] {event_type}: {src_path}" + (f" -> {dest_path}" if dest_path else ""))

        matched_objects = self._find_protected_object(src_path)
        if not matched_objects and dest_path:
            matched_objects = self._find_protected_object(dest_path)

        for obj in matched_objects:
            risk = RISK_MAP.get(event_type, 'Medium')
            new_hash = None
            previous_hash = obj.get('current_hash')

            # Calculate new hash for modified files
            if event_type == 'Modified' and os.path.isfile(src_path):
                new_hash = calculate_hash(src_path)
                if new_hash and previous_hash and new_hash != previous_hash:
                    # Integrity changed — escalate risk
                    risk = 'High'
                    execute_query(
                        "UPDATE protected_objects SET current_hash = %s, integrity_status = 'Changed', updated_at = NOW() WHERE id = %s",
                        (new_hash, obj['id'])
                    )
                elif new_hash and previous_hash and new_hash == previous_hash:
                    # Content unchanged (metadata-only change)
                    risk = 'Low'

            elif event_type == 'Created' and os.path.isfile(src_path):
                new_hash = calculate_hash(src_path)

            elif event_type == 'Deleted':
                # File was deleted — mark integrity as Changed
                execute_query(
                    "UPDATE protected_objects SET integrity_status = 'Changed', updated_at = NOW() WHERE id = %s",
                    (obj['id'],)
                )

            # Record file event (user_id=NULL for OS-level events)
            event_id = execute_query(
                "INSERT INTO file_events (protected_object_id, user_id, event_type, file_path, previous_hash, new_hash, risk_level) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (obj['id'], None, event_type, src_path, previous_hash, new_hash, risk)
            )

            # Record audit log
            execute_query(
                "INSERT INTO audit_logs (user_id, action, object_type, object_id, description, ip_address, status) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (None, f'File {event_type}', 'ProtectedObject', obj['id'],
                 f"Watchdog detected: {event_type} at {src_path}", 'System', 'Success')
            )

            # Generate alert for Medium risk and above
            if risk in ('Medium', 'High', 'Critical') and event_id:
                title = ALERT_TITLES.get(event_type, f'File {event_type}')
                severity = risk

                # Special case: integrity changed on modify
                if event_type == 'Modified' and risk == 'High':
                    title = 'File Integrity Changed'
                    desc = (f"Protected object '{obj['name']}' integrity has changed. "
                            f"Previous hash: {previous_hash[:16]}... New hash: {new_hash[:16]}... "
                            f"Path: {src_path}")
                elif event_type == 'Deleted':
                    desc = (f"Protected object '{obj['name']}' was DELETED from the file system. "
                            f"Path: {src_path}. Immediate investigation required.")
                else:
                    desc = (f"Protected object '{obj['name']}' was {event_type.lower()}. "
                            f"Path: {src_path}")

                execute_query(
                    "INSERT INTO alerts (event_id, title, description, severity, status) "
                    "VALUES (%s, %s, %s, %s, 'New')",
                    (event_id, title, desc, severity)
                )
                print(f"  [ALERT] {severity}: {title}")

    def on_created(self, event):
        if not event.is_directory:
            self._process_event('Created', event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self._process_event('Deleted', event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._process_event('Modified', event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._process_event('Moved', event.src_path, event.dest_path)


class MonitorDaemon:
    """
    Manages the Watchdog observer and dynamically watches
    paths registered in the protected_objects table.
    """

    def __init__(self):
        self.observer = Observer()
        self.event_handler = SecureTrackHandler()
        self.monitored_paths = set()
        self._running = False
        self._lock = threading.Lock()

    def start(self):
        """Start the observer."""
        if not self._running:
            self.observer.start()
            self._running = True
            print("[MONITOR] Watchdog Observer started.")

    def stop(self):
        """Stop the observer."""
        if self._running:
            self.observer.stop()
            self.observer.join(timeout=5)
            self._running = False
            print("[MONITOR] Watchdog Observer stopped.")

    def update_watches(self):
        """
        Continuously poll the database for protected objects and
        add/update watches as needed. Runs in a loop.
        """
        while self._running:
            try:
                objects = fetch_all(
                    "SELECT * FROM protected_objects WHERE monitoring_status = 'Active'"
                )
                current_paths = set()
                for obj in objects:
                    path = obj['path']
                    if os.path.exists(path):
                        current_paths.add(path)

                # Schedule new paths
                with self._lock:
                    new_paths = current_paths - self.monitored_paths
                    for path in new_paths:
                        try:
                            is_dir = os.path.isdir(path)
                            watch_path = path if is_dir else os.path.dirname(path)
                            if watch_path and os.path.isdir(watch_path):
                                self.observer.schedule(
                                    self.event_handler, watch_path, recursive=is_dir
                                )
                                self.monitored_paths.add(path)
                                print(f"  [MONITOR] Now watching: {path}")
                        except Exception as e:
                            print(f"  [MONITOR] Error scheduling {path}: {e}")

            except Exception as e:
                print(f"  [MONITOR] Error polling DB: {e}")

            time.sleep(5)  # Poll every 5 seconds


# Global monitor instance
_monitor_daemon = None


def get_monitor():
    """Get or create the global monitor daemon instance."""
    global _monitor_daemon
    if _monitor_daemon is None:
        _monitor_daemon = MonitorDaemon()
    return _monitor_daemon


def start_monitor_thread():
    """Start the monitor daemon in a background thread. Called from Flask app."""
    daemon = get_monitor()
    daemon.start()

    poll_thread = threading.Thread(target=daemon.update_watches, daemon=True)
    poll_thread.start()
    print("[MONITOR] Background monitoring thread started.")
    return daemon


def stop_monitor():
    """Stop the monitor daemon."""
    global _monitor_daemon
    if _monitor_daemon:
        _monitor_daemon._running = False
        _monitor_daemon.stop()
        _monitor_daemon = None


# Standalone mode
if __name__ == "__main__":
    print("=" * 50)
    print("  SecureTrack File Monitor (Standalone)")
    print("=" * 50)
    daemon = MonitorDaemon()
    daemon.start()
    daemon._running = True
    try:
        daemon.update_watches()
    except KeyboardInterrupt:
        print("\n[MONITOR] Shutting down...")
        daemon._running = False
        daemon.stop()
