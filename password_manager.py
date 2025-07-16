import sqlite3
from pathlib import Path

from cryptography.fernet import Fernet
import base64
import hashlib

import tkinter as tk
from tkinter import ttk, messagebox

DB_FILE = "passwords.db"
dropdown = None
password_list = None
password_display_map = {}
root = None

def init_db():
    with sqlite3.connect(DB_FILE) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS passwords (
                context TEXT PRIMARY KEY,
                password TEXT NOT NULL
            );
        """)
        db.commit()

def get_key(secret="my-app-secret"):
    salt = b"static-salt-1234"
    kdf = hashlib.pbkdf2_hmac('sha256', secret.encode(), salt, 100_000)
    return base64.urlsafe_b64encode(kdf[:32])

def encrypt_password(password: str) -> str:
    key = get_key()
    f = Fernet(key)
    return f.encrypt(password.encode()).decode()

def decrypt_password(encrypted: str) -> str:
    key = get_key()
    f = Fernet(key)
    return f.decrypt(encrypted.encode()).decode()

def get_password(context):
    with sqlite3.connect(DB_FILE) as db:
        cursor = db.execute("SELECT password FROM passwords WHERE context = ?", (context,))
        rows = cursor.fetchone()
        if len(rows) > 0:
            return decrypt_password(rows[0])
        return ""
    
def get_contexts():
    with sqlite3.connect(DB_FILE) as db:
        cursor = db.execute("SELECT context FROM passwords")
        rows = cursor.fetchall()
        return [
            r[0] for r in rows
        ]

def add_password(context, password):
    enc_password = encrypt_password(password)
    with sqlite3.connect(DB_FILE) as db:
        db.execute("INSERT INTO passwords (context, password) VALUES (?, ?)", (context, enc_password))
        db.commit()
    reload_context()

def delete_password(context):
    with sqlite3.connect(DB_FILE) as db:
        db.execute("DELETE FROM passwords WHERE context = ?", (context, ))
        db.commit()
    reload_context()


def reload_context():
    global password_list
    password_list.delete(0, tk.END)
    password_display_map.clear()
    contexts = get_contexts()
    for i, context in enumerate(contexts):
        password_list.insert(tk.END, context)
        password_display_map[i] = context


def copy_password_to_clipboard(root):
    selection = password_list.curselection()
    if not selection:
        messagebox.showwarning("No selection", "Please select a context to copy the password.")
        return
    
    index = selection[0]
    context = password_display_map.get(index)
    password = get_password(context)
    root.clipboard_clear()
    root.clipboard_append(password)
    # messagebox.showinfo("Info", f"Password for {selected} is : {password}")


def delete_selected_password():
    selection = password_list.curselection()
    if not selection:
        messagebox.showwarning("No selection", "Please select a context to delete password.")
        return
    index = selection[0]
    context = password_display_map.get(index)
    delete_password(context)
    reload_context()

def copy_password_to_clipboard_dbl_click(event):
    global root
    copy_password_to_clipboard(root)


def build_gui():
    # Create main window
    global root
    root = tk.Tk()
    root.title("Password Manager")
    root.geometry("300x350")

    global password_list
    password_list = tk.Listbox(root, width=50, height=5)
    password_list.pack(pady=10)

    password_list.bind("<Double-Button-1>", copy_password_to_clipboard_dbl_click)

    reload_context()

    # Create button
    button = tk.Button(root, text="Copy Password to Clipboard", command=lambda : copy_password_to_clipboard(root))
    button.pack(pady=5)

    ttk.Separator(root, orient="horizontal").pack(fill="x", pady=10)

    delete_button = tk.Button(root, text="Delete Password", command=lambda : delete_selected_password())
    delete_button.pack(pady=5)

    # Add new context
    tk.Label(root, text="Add New Context:").pack()
    context_entry = tk.Entry(root)
    context_entry.pack(pady=2)

    tk.Label(root, text="Enter Password:").pack()
    password_entry = tk.Entry(root, show="*")
    password_entry.pack(pady=2)

    tk.Button(root, text="Add Password", command=lambda: add_password(context_entry.get().strip(), password_entry.get().strip())).pack(pady=10)

    # Run the application
    root.mainloop()


if __name__ == "__main__":
    init_db()
    build_gui()

