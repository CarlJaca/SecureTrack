import os, time
from db import execute_query, fetch_all

print('1. Creating test file')
os.makedirs('SecureFiles', exist_ok=True)
with open('SecureFiles/rename_test.txt', 'w') as f:
    f.write('hello world')

print('2. Adding to protected objects')
path = os.path.abspath('SecureFiles/rename_test.txt')
execute_query('INSERT INTO protected_objects (name, path, object_type, monitoring_status) VALUES (%s, %s, %s, %s)', 
              ('rename_test', path, 'File', 'Active'))

print('3. Waiting 6 seconds for monitor to pick it up')
time.sleep(6)

print('4. Renaming file')
os.rename('SecureFiles/rename_test.txt', 'SecureFiles/rename_test_new.txt')

print('5. Waiting 3 seconds for event to process')
time.sleep(3)

print('6. Checking database for events')
events = fetch_all('SELECT event_type, file_path FROM file_events ORDER BY id DESC LIMIT 5')
print('Events:')
for e in events:
    print(f'- {e["event_type"]}: {e["file_path"]}')
