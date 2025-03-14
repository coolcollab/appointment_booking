import sqlite3
import hashlib

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Admin options
while True:
    print("\n1. Add Admin User")
    print("2. View All Users")
    print("3. Delete a User")
    print("4. Exit")
    choice = input("Enter your choice: ")

    conn = sqlite3.connect("rootdb.db")
    c = conn.cursor()

    if choice == "1":
        username = input("Enter new admin username: ")
        password = input("Enter new admin password: ")
        hashed_password = hash_password(password)
        c.execute("INSERT INTO admin (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        print("✅ Admin user added successfully!")
    
    elif choice == "2":
        c.execute("SELECT id, username FROM admin")
        users = c.fetchall()
        print("\nRegistered Admin Users:")
        for user in users:
            print(f"ID: {user[0]}, Username: {user[1]}")
    
    elif choice == "3":
        user_id = input("Enter the ID of the user to delete: ")
        c.execute("DELETE FROM admin WHERE id = ?", (user_id,))
        conn.commit()
        print("✅ User deleted successfully!")
    
    elif choice == "4":
        conn.close()
        print("Exiting...")
        break
    
    else:
        print("Invalid choice! Please enter a valid option.")

    conn.close()
