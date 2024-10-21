import sqlite3

# Connect to (or create) a SQLite database
conn = sqlite3.connect('network_packets.db')
cursor = conn.cursor()

# Create a table to store packet data
cursor.execute('''
    CREATE TABLE IF NOT EXISTS packets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        src_ip TEXT,
        dest_ip TEXT,
        protocol TEXT,
        length INTEGER,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
''')
conn.commit()
print("Database setup completed!")
