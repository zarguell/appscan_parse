import sqlite3
import time

# Connect to the database
conn = sqlite3.connect('./issues.db')
c = conn.cursor()

# Calculate the timestamp for 1 week ago
one_week_ago = int(time.time()) - (7 * 24 * 60 * 60)

# Update the first_found and last_found fields of all issues
c.execute("""
    UPDATE issues
    SET first_found = ?, last_found = ?
""", (one_week_ago, one_week_ago))

# Commit and close the database connection
conn.commit()
conn.close()
