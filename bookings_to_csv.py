import sqlite3
import csv

# Connect to the database
conn = sqlite3.connect("rootdb.db")
cursor = conn.cursor()

# Fetch all data from bookings
cursor.execute("SELECT * FROM bookings")
rows = cursor.fetchall()

# Get column names
column_names = [desc[0] for desc in cursor.description]

# Write to CSV
with open("bookings_export.csv", "w", newline="") as file:
    writer = csv.writer(file)
    writer.writerow(column_names)  # Write header
    writer.writerows(rows)  # Write data

conn.close()
print("✅ Data exported to bookings_export.csv successfully!")
