import sqlite3
import csv

# Connect to the database
conn = sqlite3.connect("rootdb.db")
cursor = conn.cursor()

# Fetch all data from admin
cursor.execute("SELECT * FROM admin")
rows = cursor.fetchall()

# Get column names
column_names = [desc[0] for desc in cursor.description]

# Write to CSV
with open("admin_export.csv", "w", newline="") as file:
    writer = csv.writer(file)
    writer.writerow(column_names)
    writer.writerows(rows)

conn.close()
print("✅ Data exported to admin_export.csv successfully!")
