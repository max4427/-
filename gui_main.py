
import tkinter as tk
from tkinter import messagebox
import socket
import json
import time
from auth_and_crud import (
    sign_up, add_profile, delete_profile,
    update_behavior, show_profiles
)

root = tk.Tk()
root.title("User Authentication & Profiles")
root.configure(bg="#F0F4F8")

current_user_role = None
Admin_Code = "1234"

def is_input_safe(value):
    blacklist = [";", "--", "'", '"', "/*", "*/", "xp_", "union", "select", "insert", "drop", "delete", "update"]
    return not any(term in value.lower() for term in blacklist)

def send_server_request(request):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", 8080))
        s.send(json.dumps(request).encode("utf-8"))
        data = s.recv(4096).decode("utf-8")
        s.close()
        return json.loads(data)
    except Exception as e:
        messagebox.showerror("Server Error", str(e))
        return {}

def show_blocked_time(seconds):
    blocked_label = tk.Label(login_frame, text="", font=("Arial", 12), bg="#F0F4F8", fg="red")
    blocked_label.grid(row=5, columnspan=2, pady=5)

    def countdown(t):
        if t <= 0:
            blocked_label.destroy()
            return
        blocked_label.config(text=f"Too many failed attempts. Try again in {t} seconds.")
        root.after(1000, countdown, t - 1)

    countdown(seconds)


def login(entry_username, entry_password, show_home_page):
    username = entry_username.get().strip()
    password = entry_password.get().strip()
    if not username or not password:
        messagebox.showerror("Error", "Username and password must be filled out.")
        return
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(("127.0.0.1", 8080))
        client.send(json.dumps({
            "action": "login",
            "username": username,
            "password": password
        }).encode("utf-8"))
        response = json.loads(client.recv(4096).decode("utf-8"))
        client.close()
        if response.get("blocked"):
            seconds = response.get("retry_after", 60)
            show_blocked_time(seconds)
            return
        code = response.get("code")
        if code == 0:
            messagebox.showerror("Login Failed", "Invalid username or password.")
        elif code == 1:
            global current_user_role
            current_user_role = "worker"
            messagebox.showinfo("Login Success", "Welcome, worker!")
            show_home_page()
        elif code == 2:
            current_user_role = "admin"
            messagebox.showinfo("Login Success", "Welcome, admin!")
            show_home_page()
        else:
            messagebox.showerror("Error", "Unexpected response from server.")
    except Exception as e:
        messagebox.showerror("Connection Error", str(e))

signup_frame = tk.Frame(root, bg="#F0F4F8")
login_frame = tk.Frame(root, bg="#F0F4F8")
home_frame = tk.Frame(root, bg="#F0F4F8")
manage_profiles_frame = tk.Frame(root, bg="#F0F4F8")
manage_users_frame = tk.Frame(root, bg="#F0F4F8")

signup_frame = tk.Frame(root, bg="#F0F4F8")
tk.Label(signup_frame, text="Sign Up", font=("Arial", 16), bg="#F0F4F8").grid(row=0, columnspan=2, pady=10)

tk.Label(signup_frame, text="Username:", bg="#F0F4F8").grid(row=1, column=0)
entry_username_signup = tk.Entry(signup_frame)
entry_username_signup.grid(row=1, column=1)

tk.Label(signup_frame, text="Password:", bg="#F0F4F8").grid(row=2, column=0)
entry_password_signup = tk.Entry(signup_frame, show="*")
entry_password_signup.grid(row=2, column=1)

tk.Label(signup_frame, text="Role:", bg="#F0F4F8").grid(row=3, column=0)
role_var_signup = tk.StringVar(value="worker")
tk.Radiobutton(signup_frame, text="Admin", variable=role_var_signup, value="admin", bg="#F0F4F8").grid(row=3, column=1)
tk.Radiobutton(signup_frame, text="Worker", variable=role_var_signup, value="worker", bg="#F0F4F8").grid(row=4, column=1)

tk.Label(signup_frame, text="Admin Key:", bg="#F0F4F8").grid(row=5, column=0)
entry_admin_key = tk.Entry(signup_frame, show="*")
entry_admin_key.grid(row=5, column=1)

def validate_and_sign_up():
    username = entry_username_signup.get().strip()
    password = entry_password_signup.get().strip()
    role = role_var_signup.get()
    admin_key = entry_admin_key.get().strip()

    if not username or not password:
        messagebox.showerror("Error", "Username and password must be filled out.")
        return

    if not is_input_safe(username) or not is_input_safe(password):
        messagebox.showerror("Error", "Invalid characters or not authorized keywords in input.")
        return

    if role == "admin" and admin_key != Admin_Code:
        messagebox.showerror("Error", "Invalid admin key.")
        return

    sign_up(entry_username_signup, entry_password_signup, role_var_signup, show_login_page)

tk.Button(signup_frame, text="Register", command=validate_and_sign_up, bg="#4A90E2", fg="white").grid(row=6, columnspan=2, pady=10)
tk.Button(signup_frame, text="Back to Login", command=lambda: show_login_page(), bg="#999999", fg="white").grid(row=7, columnspan=2)


login_frame = tk.Frame(root, bg="#F0F4F8")
tk.Label(login_frame, text="Login", font=("Arial", 16), bg="#F0F4F8").grid(row=0, columnspan=2, pady=10)

tk.Label(login_frame, text="Username:", bg="#F0F4F8").grid(row=1, column=0)
entry_username_login = tk.Entry(login_frame)
entry_username_login.grid(row=1, column=1)

tk.Label(login_frame, text="Password:", bg="#F0F4F8").grid(row=2, column=0)
entry_password_login = tk.Entry(login_frame, show="*")
entry_password_login.grid(row=2, column=1)

tk.Button(login_frame, text="Login", command=lambda: login(entry_username_login, entry_password_login, show_home_page), bg="#4A90E2", fg="white").grid(row=3, columnspan=2, pady=10)
tk.Button(login_frame, text="Sign Up", command=lambda: show_signup_page(), bg="#999999", fg="white").grid(row=4, columnspan=2)


home_frame = tk.Frame(root, bg="#F0F4F8")
tk.Button(home_frame, text="View Profiles", command=lambda: show_profiles(profile_text), bg="#4A90E2", fg="white").grid(row=0, column=0)
tk.Button(home_frame, text="Manage Profiles", command=lambda: show_manage_profiles(), bg="#4A90E2", fg="white").grid(row=0, column=1)
tk.Button(home_frame, text="Manage Users", command=lambda: show_manage_users(), bg="#4A90E2", fg="white").grid(row=0, column=2)
tk.Button(home_frame, text="Logout", command=lambda: show_login_page(), bg="#4A90E2", fg="white").grid(row=1, column=0)
profile_text = tk.Text(home_frame, height=10, width=80)
profile_text.grid(row=2, column=0, columnspan=3)


manage_profiles_frame = tk.Frame(root, bg="#F0F4F8")

def clear_manage_fields():
    for widget in manage_profiles_frame.winfo_children():
        if isinstance(widget, tk.Entry):
            widget.delete(0, tk.END)

def show_manage_profiles():
    home_frame.grid_forget()
    clear_manage_fields()
    manage_profiles_frame.grid(row=0, column=0, padx=20, pady=20)

tk.Label(manage_profiles_frame, text="Name:", bg="#F0F4F8").grid(row=0, column=0)
entry_name = tk.Entry(manage_profiles_frame)
entry_name.grid(row=0, column=1)

tk.Label(manage_profiles_frame, text="Age:", bg="#F0F4F8").grid(row=1, column=0)
entry_age = tk.Entry(manage_profiles_frame)
entry_age.grid(row=1, column=1)

tk.Label(manage_profiles_frame, text="Description:", bg="#F0F4F8").grid(row=2, column=0)
entry_description = tk.Entry(manage_profiles_frame)
entry_description.grid(row=2, column=1)

tk.Label(manage_profiles_frame, text="Behavior:", bg="#F0F4F8").grid(row=3, column=0)
entry_behavior = tk.Entry(manage_profiles_frame)
entry_behavior.grid(row=3, column=1)

def validate_and_add_profile():
    if current_user_role != "admin":
        messagebox.showerror("Permission Denied", "Only admins can add profiles.")
        return
    if not all([entry_name.get(), entry_age.get(), entry_description.get(), entry_behavior.get()]):
        messagebox.showerror("Error", "All fields must be filled out.")
        return
    if not all(map(is_input_safe, [entry_name.get(), entry_age.get(), entry_description.get(), entry_behavior.get()])):
        messagebox.showerror("Error", "Invalid characters in input.")
        return
    add_profile(entry_name, entry_age, entry_description, entry_behavior, lambda: show_profiles(profile_text))

tk.Button(manage_profiles_frame, text="Add Profile", command=validate_and_add_profile, bg="#4A90E2", fg="white").grid(row=4, columnspan=2)

tk.Label(manage_profiles_frame, text="Delete Profile ID:", bg="#F0F4F8").grid(row=5, column=0)
entry_delete_id = tk.Entry(manage_profiles_frame)
entry_delete_id.grid(row=5, column=1)

def validate_and_delete_profile():
    if current_user_role != "admin":
        messagebox.showerror("Permission Denied", "Only admins can delete profiles.")
        return
    if not entry_delete_id.get() or not is_input_safe(entry_delete_id.get()):
        messagebox.showerror("Error", "Invalid or empty Profile ID.")
        return
    delete_profile(entry_delete_id, lambda: show_profiles(profile_text))

tk.Button(manage_profiles_frame, text="Delete Profile", command=validate_and_delete_profile, bg="#4A90E2", fg="white").grid(row=6, columnspan=2)

tk.Label(manage_profiles_frame, text="Update Behavior Profile ID:", bg="#F0F4F8").grid(row=7, column=0)
entry_behavior_id = tk.Entry(manage_profiles_frame)
entry_behavior_id.grid(row=7, column=1)

tk.Label(manage_profiles_frame, text="New Behavior:", bg="#F0F4F8").grid(row=8, column=0)
entry_new_behavior = tk.Entry(manage_profiles_frame)
entry_new_behavior.grid(row=8, column=1)

def validate_and_update_behavior():
    if not entry_behavior_id.get() or not entry_new_behavior.get():
        messagebox.showerror("Error", "Fields must not be empty.")
        return
    if not is_input_safe(entry_behavior_id.get()) or not is_input_safe(entry_new_behavior.get()):
        messagebox.showerror("Error", "Invalid input.")
        return
    update_behavior(entry_behavior_id, entry_new_behavior, lambda: show_profiles(profile_text))

tk.Button(manage_profiles_frame, text="Update Behavior", command=validate_and_update_behavior, bg="#4A90E2", fg="white").grid(row=9, columnspan=2)
tk.Button(manage_profiles_frame, text="Back to Home", command=lambda: show_home_page(), bg="#999999", fg="white").grid(row=10, columnspan=2)


manage_users_frame = tk.Frame(root, bg="#F0F4F8")

def load_users():
    result = send_server_request({"action": "get_users"})
    user_list.delete(0, tk.END)
    for user in result.get("users", []):
        user_list.insert(tk.END, f"ID: {user[0]} | Name: {user[1]} | Role: {user[2]}")

def update_user_role():
    user_id = entry_user_id.get()
    new_role = role_var_update.get()
    if current_user_role != "admin":
        messagebox.showerror("Permission Denied", "Only admins can add profiles.")
        return
    if not user_id or not new_role:
        messagebox.showerror("Error", "Fill in both fields")
        return
    result = send_server_request({"action": "update_role", "user_id": int(user_id), "new_role": new_role})
    if result.get("status") == "updated":
        messagebox.showinfo("Success", "User role updated.")
        load_users()
    else:
        messagebox.showerror("Error", "Failed to update role")

def delete_user():
    user_id = entry_user_id.get()
    if current_user_role != "admin":
        messagebox.showerror("Permission Denied", "Only admins can delete users.")
        return
    if not user_id:
        messagebox.showerror("Error", "Enter User ID to delete")
        return
    result = send_server_request({"action": "delete_user", "user_id": int(user_id)})
    if result.get("status") == "deleted":
        messagebox.showinfo("Success", "User deleted successfully.")
        load_users()
    else:
        messagebox.showerror("Error", "Failed to delete user")

def filter_users():
    role_filter = filter_role_var.get()
    result = send_server_request({"action": "get_users"})
    user_list.delete(0, tk.END)
    for user in result.get("users", []):
        if role_filter == "all" or user[2] == role_filter:
            user_list.insert(tk.END, f"ID: {user[0]} | Name: {user[1]} | Role: {user[2]}")

tk.Label(manage_users_frame, text="All Users:", bg="#F0F4F8").pack()
user_list = tk.Listbox(manage_users_frame, width=80)
user_list.pack()

frame_edit = tk.Frame(manage_users_frame, bg="#F0F4F8")
tk.Label(frame_edit, text="User ID:", bg="#F0F4F8").grid(row=0, column=0)
entry_user_id = tk.Entry(frame_edit)
entry_user_id.grid(row=0, column=1)

role_var_update = tk.StringVar()
tk.Radiobutton(frame_edit, text="Admin", variable=role_var_update, value="admin", bg="#F0F4F8").grid(row=1, column=0)
tk.Radiobutton(frame_edit, text="Worker", variable=role_var_update, value="worker", bg="#F0F4F8").grid(row=1, column=1)

tk.Button(frame_edit, text="Update Role", command=update_user_role, bg="#4A90E2", fg="white").grid(row=2, columnspan=2, pady=5)
tk.Button(frame_edit, text="Delete User", command=delete_user, bg="#e74c3c", fg="white").grid(row=3, columnspan=2, pady=5)
frame_edit.pack()

filter_frame = tk.Frame(manage_users_frame, bg="#F0F4F8")
tk.Label(filter_frame, text="Filter by Role:", bg="#F0F4F8").pack(side=tk.LEFT)
filter_role_var = tk.StringVar(value="all")
tk.OptionMenu(filter_frame, filter_role_var, "all", "admin", "worker").pack(side=tk.LEFT)
tk.Button(filter_frame, text="Apply Filter", command=filter_users, bg="#4A90E2", fg="white").pack(side=tk.LEFT, padx=10)
filter_frame.pack(pady=10)

tk.Button(manage_users_frame, text="Back to Home", command=lambda: show_home_page(), bg="#999999", fg="white").pack()

def show_home_page():
    login_frame.grid_forget()
    signup_frame.grid_forget()
    manage_profiles_frame.grid_forget()
    manage_users_frame.grid_forget()
    home_frame.grid(row=0, column=0, padx=20, pady=20)

def show_login_page():
    signup_frame.grid_forget()
    home_frame.grid_forget()
    manage_profiles_frame.grid_forget()
    manage_users_frame.grid_forget()
    login_frame.grid(row=0, column=0, padx=20, pady=20)

def show_signup_page():
    login_frame.grid_forget()
    signup_frame.grid(row=0, column=0, padx=20, pady=20)

def show_manage_profiles():
    home_frame.grid_forget()
    manage_profiles_frame.grid(row=0, column=0, padx=20, pady=20)

def show_manage_users():
    if current_user_role != "admin":
        messagebox.showerror("Access Denied", "Only admins can access user management.")
        return
    home_frame.grid_forget()
    load_users()
    manage_users_frame.grid(row=0, column=0, padx=20, pady=20)

show_login_page()
root.mainloop()
