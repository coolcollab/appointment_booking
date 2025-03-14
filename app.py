import sqlite3
import logging
import os
import re
import bcrypt
import pytz
from datetime import datetime
from flask_talisman import Talisman
from sqlite3 import IntegrityError
from flask import Flask, make_response, send_from_directory, render_template, request, jsonify, redirect, url_for, session
from marshmallow import Schema, fields, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import secrets
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
csrf = CSRFProtect(app)

csp = {
    'default-src': "'self'",
    'script-src': "'self' 'unsafe-inline'",
    'style-src': "'self' 'unsafe-inline' fonts.googleapis.com fonts.gstatic.com",
    'font-src': "'self' fonts.googleapis.com fonts.gstatic.com data:"
}

Talisman(app, content_security_policy=csp)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = True

if not os.path.exists("logs"):
    os.makedirs("logs")

for handler in logging.root.handlers[:]:
    logging.root.removeHandler(handler)

log_filename = datetime.now().strftime("logs/logs_%Y-%m.log")

logging.basicConfig(
    filename=log_filename,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def log_action(action, details=""):
    ip_address = request.remote_addr or "Unknown IP"
    user = session.get("admin_logged_in", "Not Logged In")
    log_message = f"IP: {ip_address} | User: {user} | Action: {action} | Details: {details}"
    logging.info(log_message)

def get_db_connection():
    db_path = os.environ.get("DATABASE_PATH", "rootdb.db")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    try:
        conn = get_db_connection()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS bookings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                customer_name TEXT,
                customer_email TEXT,
                customer_phone NUMERIC,
                booked_at_datetime DATETIME UNIQUE,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS admin (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password BLOB,
                role TEXT DEFAULT 'manager'
            )
        ''')
        conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Database initialization failed: {e}")
    finally:
        if conn:
            conn.close()

def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password

def verify_password(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

def sanitize_input(value):
    return re.sub(r"[;'\"><`\\|&]", "", value.strip())

class BookingSchema(Schema):
    name = fields.Str(required=True)
    email = fields.Email(required=True)
    phone = fields.Str(required=True, validate=lambda p: len(p) == 10)
    slot_time = fields.Str(required=True)
    date = fields.Str(required=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route("/bookSlot", methods=["POST"])
def book_slot():
    data = request.get_json()
    logging.info(f"Received Data: {data}")

    try:
        if not request.is_json:
            return jsonify({"message": "Invalid request format! Expected JSON."}), 400

        sanitized_data = {k: sanitize_input(str(v)) for k, v in data.items()}
        print("Received Data:", data)
        local_timezone = pytz.timezone("Asia/Kolkata")  # Change as necessary
        local_time = datetime.now(local_timezone)
        formatted_time = local_time.strftime("%Y-%m-%d %H:%M:%S %Z%z")
        logging.info(f"[{formatted_time}] Received Data: {data}")

        schema = BookingSchema()
        validated_data = schema.load(data)

        customer_name = validated_data["name"]
        customer_email = validated_data["email"]
        customer_phone = validated_data["phone"]
        slot_time = validated_data["slot_time"]
        selected_date = validated_data["date"]

        print("📡 Received Booking Data:", validated_data)

        if not all(key in data for key in ('name', 'email', 'phone', 'slot_time', 'date')):
            print("Missing data")

        full_datetime_str = f"{selected_date} {slot_time}"
        try:
            local_datetime = datetime.strptime(full_datetime_str, "%Y-%m-%d %I:%M %p")
        except ValueError:
            return jsonify({"message": "Invalid date or time format. Please use %Y-%m-%d 12 Hour Time format(HH:MM AM/PM)."}), 400

        local_tz = pytz.timezone("Asia/Kolkata") #Change as necessary
        local_datetime = local_tz.localize(local_datetime)
        utc_datetime = local_datetime.astimezone(pytz.utc)
        utc_datetime_str = utc_datetime.strftime("%Y-%m-%d %H:%M:%S")

        if utc_datetime < datetime.now(pytz.utc):
            log_action("Failed Booking", f"Attempted past slot: {full_datetime_str}")
            return jsonify({"message": "You cannot book a past slot!"}), 400

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM bookings WHERE booked_at_datetime = ?", (utc_datetime_str,))
        if c.fetchone():
            conn.close()
            log_action("Failed Booking", f"Slot already booked: {utc_datetime_str}")
            return jsonify({"message": "This time slot is already booked."}), 400

        c.execute("INSERT INTO bookings (customer_name, customer_email, customer_phone, booked_at_datetime) VALUES (?, ?, ?, ?)", (customer_name, customer_email, customer_phone, utc_datetime_str))
        conn.commit()
        log_action("Successful Booking", f"Name: {customer_name}, Email: {customer_email}Phone: {customer_phone}, Slot: {utc_datetime_str}")
        return jsonify({"message": "Booking successful!"}), 200

    except ValidationError as err:
        logging.error(f"Validation Error: {err.messages}")
        return jsonify(err.messages), 400

    except sqlite3.Error as e:
        conn.rollback() 
        logging.error(f"Database Error: {e}")
        return jsonify({"message": "Database error occurred"}), 500

    except Exception as e:
        logging.error(f"Booking Error: {e}")
        return jsonify({"message": "An error occurred"}), 500
    finally:
        if 'conn' in locals() and conn:
            conn.close()

class AdminLoginSchema(Schema):
    username = fields.Str(required=True)
    password = fields.Str(required=True)

@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    if "failed_attempts" not in session:
        session["failed_attempts"] = 0

    if request.method == "POST":
        csrf_token = request.form.get("csrf_token")
        print(csrf_token())
        if not csrf_token or csrf_token != session.get("csrf_token"):
            return render_template("admin_login.html", error="CSRF token validation failed.")
        
        try:
            schema = AdminLoginSchema()
            validated_data = schema.load(request.form)

            username = validated_data["username"]
            password = validated_data["password"]

            print("📡 Received POST request: ImmutableMultiDict([('username', '{}')])".format(username))

            conn = get_db_connection()
            c = conn.cursor()
            c.execute("SELECT id, username, password, role FROM admin WHERE username = ?", (username,))
            admin = c.fetchone()
            conn.close()

            if admin:
                    app.logger.info(f"User {username} found in database.")
                    if verify_password(password, admin[2]):
                        app.logger.info(f"Password verified for {username}.")
                        session.regenerate()
                        session["admin_logged_in"] = True
                        session["admin_id"] = admin[0]
                        session["admin_username"] = admin[1]
                        session["admin_role"] = admin[3]
                        session["failed_attempts"] = 0
                        log_action("Admin Login Successful", f"Username: {username}, Role: {admin[3]}")
                        return redirect(url_for("admin_panel"))
                    else:
                        app.logger.info(f"Incorrect Password for {username}")
            else:
                app.logger.info(f"User {username} not found.")

            session["failed_attempts"] += 1
            log_action("Failed Admin Login", f"Username: {username}, Attempt: {session['failed_attempts']}")

            if session["failed_attempts"] > 5:
                log_action("Brute-force Alert", f"Username: {username} - Too many failed login attempts")
                return jsonify({"message": "Too many failed attempts. Try again later."}), 403

            return render_template("admin_login.html", error="Invalid credentials", csrf_token=session['csrf_token'])

        except ValidationError as err:
            app.logger.error(f"Validation error during login: {err}")
            return render_template("admin_login.html", error=err.messages, csrf_token=session['csrf_token'])

        except Exception as e:
            app.logger.error(f"Admin login error: {e}")
            log_action("Admin Login Error", str(e))
            return render_template("admin_login.html", error="An unexpected error occurred.", csrf_token=session['csrf_token'])

    else:
        return render_template("admin_login.html", csrf_token=session['csrf_token'])
    
@app.route("/admin/panel")
def admin_panel():
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))

    role = session.get("admin_role")
    print(session)
    return render_template("admin_panel.html", role=role)

@app.route('/admin/logout')
def admin_logout():
    log_action("Admin Logout", f"User: {session.get('admin_logged_in')}")
    session.pop("admin_logged_in", None)
    return redirect(url_for("admin_login"))

@app.route("/manageUsers")
def manage_users():
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))
    
    if session.get('admin_role') == 'root':
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT id, username, role FROM admin") #Select id, username, and role.
        users = c.fetchall()
        conn.close()
        return render_template('manage_users.html', users=users)
    else:
        return "Access Denied"

@app.route("/addUser", methods=["POST"])
def add_user():
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))
    if session.get('admin_role') == 'root':
        data = request.json
        username = data.get("username", "").strip()
        password = data.get('password')
        role = data.get('role')

        if not username or not password or not role:
            return jsonify({'message': 'Missing username, password, or role'}), 400

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        conn = get_db_connection()
        c = conn.cursor()
        try:
            c.execute("INSERT INTO admin (username, password, role) VALUES (?, ?, ?)", (username, hashed_password, role))
            conn.commit()
            log_action("User Added", f"Username: {username}")
            return jsonify({"message": "User added successfully!"}), 200
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({'message': 'Username already exists'}), 400
    else:
        return jsonify({'message': 'Access denied'}), 403
    
@app.route('/deleteUser', methods=['POST'])
def delete_user():
    if not session.get("admin_logged_in"):
        return jsonify({"message": "Unauthorized access!"}), 403
    
    data = request.get_json()
    if not data or "id" not in data:
        return jsonify({"message": "Invalid request, user ID missing!"}), 400
    
    user_id = data.get("id")

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT username FROM admin WHERE id = ?", (user_id,))
    user = c.fetchone()
    
    if user:
        c.execute("DELETE FROM admin WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()
        log_action("User Deleted", f"Username: {user[0]}")
        return jsonify({"message": f"User {user[0]} deleted successfully!"}), 200
    else:
        conn.close()
        log_action("Failed to Delete User", f"User ID: {user_id} not found")
        return jsonify({"message": "User not found!"}), 404

@app.route('/viewBookings')
def view_bookings():
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))
    
    conn = get_db_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("SELECT id, customer_name, customer_email, customer_phone, booked_at_datetime, created_at FROM bookings WHERE booked_at_datetime >= ? ORDER BY booked_at_datetime", (now,))
    bookings = c.fetchall()
    conn.close()

    log_action("Viewed Bookings", f"Total: {len(bookings)}")
    return render_template("view_bookings.html", bookings=bookings)

@app.route('/getAvailableSlots')
def get_available_slots():
    date = request.args.get("date")
    if not date:
        return jsonify({"error": "Missing date parameter"}), 400
    
    try:
        datetime.strptime(date, "%Y-%m-%d") #Test the date format.
    except ValueError:
        return jsonify({"error": "Invalid date format, use YYYY-MM-DD"}), 400
    
    all_slots = ["10:00 AM", "11:00 AM", "12:00 PM", "02:00 PM", "03:00 PM"]
    booked_slots = set()

    conn = get_db_connection()
    c = conn.cursor()
    for slot in all_slots:
        try:
            local_datetime = datetime.strptime(f"{date} {slot}", "%Y-%m-%d %I:%M %p")
            local_tz = pytz.timezone("Asia/Kolkata")
            local_datetime = local_tz.localize(local_datetime)
            utc_datetime = local_datetime.astimezone(pytz.utc)
            utc_datetime_str = utc_datetime.strftime("%Y-%m-%d %H:%M:%S")

            c.execute("SELECT 1 FROM bookings WHERE booked_at_datetime = ?", (utc_datetime_str,))
            if c.fetchone():
                booked_slots.add(slot)
        except ValueError:
            return jsonify({"error": "invalid date or time format"}), 400
    conn.close()

    available_slots = [slot for slot in all_slots if slot not in booked_slots]
    
    log_action("Checked Available Slots", f"Date: {date}, Available: {available_slots}")
    
    return jsonify({"availableSlots": available_slots})

@app.route("/pastBookings")
def past_bookings():
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))
    
    conn = get_db_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("SELECT id, customer_name, customer_email, customer_phone, booked_at_datetime, created_at FROM bookings WHERE booked_at_datetime < ? ORDER BY booked_at_datetime DESC", (now,))
    past_bookings = c.fetchall()
    conn.close()

    return render_template("past_bookings.html", bookings=past_bookings)

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
