import sqlite3
import hashlib
import bcrypt
from tkinter import messagebox

# פונקציית יצירת טבלאות במסד הנתונים
def create_tables():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('admin', 'worker')))''')
    c.execute('''CREATE TABLE IF NOT EXISTS profiles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    age INTEGER NOT NULL,
                    description TEXT NOT NULL,
                    behavior TEXT NOT NULL)''')
    conn.commit()
    conn.close()

# בדיקת קלט בטוח
def is_input_safe(value):
    blacklist = [";", "--", "'", '"', "/*", "*/", "xp_", "union", "select", "insert", "drop", "delete", "update"]
    return not any(term in value.lower() for term in blacklist)

# הצפנת סיסמה
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# פונקציית הרשמה
def sign_up(entry_username, entry_password, role_var, show_login_page):
    username = entry_username.get().strip()
    password = entry_password.get().strip()
    role = role_var.get()

    if not username or not password:
        messagebox.showerror("Error", "Username and password must be filled out.")
        return

    if not is_input_safe(username) or not is_input_safe(password):
        messagebox.showerror("Error", "Invalid characters or SQL keywords in input.")
        return

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    hashed = hash_password(password)

    try:
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, hashed, role))
        conn.commit()
        messagebox.showinfo("Success", "User registered successfully!")
        show_login_page()
    except sqlite3.IntegrityError:
        messagebox.showerror("Error", "Username already exists!")
    conn.close()

# פונקציית התחברות
def login(entry_username, entry_password, show_home_page):
    username = entry_username.get().strip()
    password = entry_password.get().strip()

    if not username or not password:
        messagebox.showerror("Error", "Fields must be filled out.")
        return

    if not is_input_safe(username) or not is_input_safe(password):
        messagebox.showerror("Error", "Invalid input.")
        return

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT password, role FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    conn.close()

    if user and bcrypt.checkpw(password.encode(), user[0]):
        global current_user_role
        current_user_role = user[1]
        messagebox.showinfo("Success", "Login successful!")
        show_home_page()
    else:
        messagebox.showerror("Error", "Invalid username or password")

# הגדרה כללית לתפקיד המשתמש הנוכחי
current_user_role = None

# פעולות על פרופילים
def add_profile(entry_name, entry_age, entry_description, entry_behavior, refresh_func):
    name = entry_name.get()
    age = entry_age.get()
    description = entry_description.get()
    behavior = entry_behavior.get()

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("INSERT INTO profiles (name, age, description, behavior) VALUES (?, ?, ?, ?)",
              (name, age, description, behavior))
    conn.commit()
    conn.close()
    messagebox.showinfo("Success", "Profile added successfully!")
    refresh_func()

def delete_profile(entry_delete_id, refresh_func):
    profile_id = entry_delete_id.get()
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("DELETE FROM profiles WHERE id = ?", (profile_id,))
    conn.commit()
    conn.close()
    messagebox.showinfo("Success", "Profile deleted successfully!")
    refresh_func()

def update_behavior(entry_behavior_id, entry_new_behavior, refresh_func):
    profile_id = entry_behavior_id.get()
    new_behavior = entry_new_behavior.get()
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("UPDATE profiles SET behavior = ? WHERE id = ?", (new_behavior, profile_id))
    conn.commit()
    conn.close()
    messagebox.showinfo("Success", "Behavior updated successfully!")
    refresh_func()

def show_profiles(text_widget):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT * FROM profiles")
    profiles = c.fetchall()
    conn.close()
    text_widget.delete('1.0', 'end')
    for profile in profiles:
        text_widget.insert('end', f"ID: {profile[0]}, Name: {profile[1]}, Age: {profile[2]}, Description: {profile[3]}, Behavior: {profile[4]}\n")
