import socket
import threading
import json
import sqlite3
import bcrypt
import time

DB_NAME = "database.db"

failed_attempts = {}
blocked_users = {}

def get_db_connection():
    return sqlite3.connect(DB_NAME)

def register_user(username, password, role):
    if role not in ["admin", "worker"]:
        return {"status": "invalid_role"}
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username = ?", (username,))
    if c.fetchone():
        conn.close()
        return {"status": "exists"}
    hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, hashed_pw, role))
    conn.commit()
    conn.close()
    return {"status": "registered"}

def verify_login(username, password):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT password, role FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    if not row:
        return 0
    hashed, role = row
    if bcrypt.checkpw(password.encode(), hashed):
        return 2 if role == "admin" else 1
    return 0

def handle_client(client_socket):
    try:
        data = client_socket.recv(4096).decode("utf-8")
        request = json.loads(data)
        action = request.get("action")

        if action == "register":
            username = request.get("username")
            password = request.get("password")
            role = request.get("role")
            result = register_user(username, password, role)
            client_socket.send(json.dumps(result).encode("utf-8"))

        elif action == "login":
            username = request.get("username")
            password = request.get("password")
            now = time.time()

            if username in blocked_users and now < blocked_users[username]:
                retry_after = int(blocked_users[username] - now)
                print(f"[BLOCKED] User {username} tried to login while blocked ({retry_after} seconds remaining)")
                client_socket.send(json.dumps({
                    "code": 0,
                    "blocked": True,
                    "retry_after": retry_after
                }).encode("utf-8"))
                return

            code = verify_login(username, password)

            if code == 0:
                failed_attempts[username] = failed_attempts.get(username, 0) + 1
                print(f"[FAILED] Login for {username}. Attempt {failed_attempts[username]}/3")
                if failed_attempts[username] >= 3:
                    blocked_users[username] = now + 60
                    print(f"[LOCKED] User {username} blocked for 60 seconds")
            else:
                if username in failed_attempts:
                    print(f"[SUCCESS] Resetting failed attempts for {username}")
                failed_attempts[username] = 0

            client_socket.send(json.dumps({"code": code}).encode("utf-8"))

        elif action == "get_users":
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("SELECT id, username, role FROM users")
            users = c.fetchall()
            conn.close()
            client_socket.send(json.dumps({"users": users}).encode("utf-8"))

        elif action == "update_role":
            user_id = request.get("user_id")
            new_role = request.get("new_role")
            if new_role in ["admin", "worker"]:
                conn = get_db_connection()
                c = conn.cursor()
                c.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
                conn.commit()
                conn.close()
                client_socket.send(json.dumps({"status": "updated"}).encode("utf-8"))
            else:
                client_socket.send(json.dumps({"status": "invalid_role"}).encode("utf-8"))

        elif action == "delete_user":
            user_id = request.get("user_id")
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.commit()
            conn.close()
            client_socket.send(json.dumps({"status": "deleted"}).encode("utf-8"))


        else:
            client_socket.send(json.dumps({"error": "Unknown action"}).encode("utf-8"))

    except Exception as e:
        client_socket.send(json.dumps({"error": str(e)}).encode("utf-8"))
    finally:
        client_socket.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 8080))
    server.listen(5)
    print("Server running on port 8080 using database.db")
    while True:
        client_socket, _ = server.accept()
        threading.Thread(target=handle_client, args=(client_socket,)).start()

if __name__ == "__main__":
    start_server()
