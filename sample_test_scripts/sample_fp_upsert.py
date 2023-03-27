import sqlite3

def add_false_positive(conn, issue_id):
    c = conn.cursor()
    c.execute("SELECT id FROM false_positives WHERE issue_id = ?", (issue_id,))
    existing_record = c.fetchone()

    if existing_record:
        print(f"Record already exists for issue_id {issue_id}")
    else:
        c.execute("INSERT INTO false_positives (issue_id) VALUES (?)", (issue_id,))
        conn.commit()
        print(f"Added false positive for issue_id {issue_id}")


# Connect to the database
conn = sqlite3.connect('./issues.db')

issue_id = "1"
add_false_positive(conn, issue_id)

conn.commit()
conn.close()
