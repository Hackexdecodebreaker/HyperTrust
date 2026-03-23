import sqlite3

conn = sqlite3.connect('instance/hypertrust.db')
cursor = conn.cursor()
cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = [row[0] for row in cursor.fetchall()]
print("Tables:", tables)
conn.close()