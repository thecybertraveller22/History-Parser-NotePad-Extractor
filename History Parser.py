import os
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import shutil
import sqlite3
import json
import base64
import binascii
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import win32crypt  # For legacy password decryption
import time

def show_main_menu():
    """Display the main menu with two options."""
    main_menu = tk.Tk()
    main_menu.title("Main Menu")
    main_menu.geometry("1360x768")
    main_menu.configure(bg="#282c34")  # Background dark kr rhy hain yahan

    
    style = ttk.Style()
    style.theme_use('clam')  
    style.configure('TButton', font=('Helvetica', 12, 'bold'), foreground='#ffffff', background='#61afef', padding=10)
    style.map('TButton', background=[('active', '#98c379')], foreground=[('active', '#000000')])

    style.configure('TLabel', font=('Helvetica', 14), foreground='#ffffff', background='#282c34')

    # Welcome label
    ttk.Label(main_menu, text="Welcome to the Main Menu", style='TLabel').pack(pady=15)

    def open_history_parser():
        main_menu.destroy()
        history_parser()

    def open_notepad_viewer():
        main_menu.destroy()
        open_notepad_viewer_window()

    ttk.Button(main_menu, text="History Parser", command=open_history_parser).pack(pady=10)
    ttk.Button(main_menu, text="Notepad Viewer", command=open_notepad_viewer).pack(pady=10)

    main_menu.mainloop()

def open_notepad_viewer_window():
    """Notepad Viewer window."""

    def get_unsaved_notepad_files():
        """Fetch the list of unsaved Notepad++ files."""
        appdata_path = os.getenv('APPDATA')
        npp_backup_path = os.path.join(appdata_path, "Notepad++", "backup")

        if not os.path.exists(npp_backup_path):
            return None, "Backup folder not found. Please ensure Notepad++ backup is enabled."

        unsaved_files = os.listdir(npp_backup_path)
        if not unsaved_files:
            return None, "No unsaved files found."

        file_paths = {file: os.path.join(npp_backup_path, file) for file in unsaved_files}
        return file_paths, None

    def get_file_metadata(file_path):
        """Fetch the metadata of a file."""
        try:
            file_size = os.path.getsize(file_path)
            creation_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(os.path.getctime(file_path)))
            modified_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(os.path.getmtime(file_path)))
            metadata = f"Size: {file_size} bytes\nCreated: {creation_time}\nModified: {modified_time}"
            return metadata
        except Exception as e:
            return f"Error retrieving metadata: {e}"

    

##############################################################################################
    def display_file_content(event):
        """Display the content and metadata of the selected file."""
        try:
            selected_file = file_listbox.get(file_listbox.curselection())
            file_path = unsaved_files[selected_file]
            with open(file_path, 'r', encoding='utf-8') as f:
                file_content = f.read()
            content_textbox.delete(1.0, tk.END)
            content_textbox.insert(tk.END, file_content)
            metadata = get_file_metadata(file_path)
            metadata_label.config(text=metadata)
        except Exception as e:
            messagebox.showerror("Error", f"Could not read the file. Error: {e}")

    unsaved_files, error_message = get_unsaved_notepad_files()

    root = tk.Tk()
    root.title("Unsaved Notepad++ Files Viewer")
    root.geometry("1360x768")
    root.configure(bg="#2e3b4e")  # Darker background color for modern appearance

    # Add modern styling
    style = ttk.Style()
    style.theme_use('clam')
    style.configure("TLabel", background="#2e3b4e", foreground="#ffffff", font=("Helvetica", 12))
    style.configure("TButton", background="#4a90e2", foreground="#ffffff", font=("Helvetica", 12, "bold"), padding=10)
    style.configure("TListbox", padding=5, font=("Helvetica", 11))

    def open_history_parser():
        root.destroy()
        history_parser()
    def refresh():
        root.destroy()
        open_notepad_viewer_window()

    chrome_history_button = ttk.Button(root, text="History Parser", command=open_history_parser)
    chrome_history_button.pack(pady=10)

    refresh_button = ttk.Button(root, text="Refresh", command=refresh)
    refresh_button.pack(pady=10)
    if error_message:
        messagebox.showerror("Error", error_message)
        root.destroy()
    else:
        # Create a frame for listbox and text area
        main_frame = ttk.Frame(root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Left side for file list
        file_listbox = tk.Listbox(main_frame, height=15, width=30, bg="#e3f2fd", fg="#1e1e1e", font=("Arial", 12))
        file_listbox.grid(row=0, column=0, padx=10, pady=10, sticky="ns")
        file_listbox.bind('<<ListboxSelect>>', display_file_content)

        # Right side for content text box
        content_textbox = tk.Text(main_frame, wrap=tk.WORD, bg="#f5f5f5", fg="#333333", font=("Courier New", 12))
        content_textbox.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

        # Configure rows and columns for resizing
        main_frame.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)

        # Metadata label below the content text box
        metadata_label = ttk.Label(root, text="File metadata will be displayed here.", anchor="w")
        metadata_label.pack(fill=tk.X, padx=10, pady=5)

        # Insert filenames into the listbox
        for file in unsaved_files:
            file_listbox.insert(tk.END, file)

    root.mainloop()



def history_parser():
    """Fetch and display browser history and passwords."""
    def get_chrome_profiles():
        """Retrieve available Chrome user profiles, filtering only Default and Profile 1-8."""
        chrome_path = os.path.expanduser(r"~\AppData\Local\Google\Chrome\User Data")
        if not os.path.exists(chrome_path):
            messagebox.showerror("Error", "Google Chrome User Data folder not found.")
            return []
        valid_profiles = ["Default"] + [f"Profile {i}" for i in range(1, 11)]
        profiles = [f for f in os.listdir(chrome_path) if f in valid_profiles]
        return profiles

    def get_edge_profiles():
        """Retrieve available Microsoft Edge user profiles, filtering only Default and Profile 1-8."""
        edge_path = os.path.expanduser(r"~\AppData\Local\Microsoft\Edge\User Data")
        if not os.path.exists(edge_path):
            messagebox.showerror("Error", "Microsoft Edge User Data folder not found.")
            return []
        valid_profiles = ["Default"] + [f"Profile {i}" for i in range(1, 9)]
        profiles = [f for f in os.listdir(edge_path) if f in valid_profiles]
        return profiles

    def fetch_browser_history(browser_name, profile_name=None):
        """Fetch history for Chrome or Edge."""
        if browser_name == "Chrome":
            history_path = os.path.expanduser(rf"~\AppData\Local\Google\Chrome\User Data\{profile_name}\History")
        elif browser_name == "Edge":
            history_path = os.path.expanduser(rf"~\AppData\Local\Microsoft\Edge\User Data\{profile_name}\History")
        else:
            messagebox.showerror("Error", "Invalid browser name.")
            return []

        if os.path.exists("tempBrowserHist"):
            os.remove("tempBrowserHist")

        if not os.path.exists(history_path):
            messagebox.showerror("Error", f"{browser_name} history file not found.")
            return []

        shutil.copy(history_path, "tempBrowserHist")
        temp_path = "tempBrowserHist"

        try:
            uri = f"file:{temp_path}?mode=ro"
            conn = sqlite3.connect(uri, uri=True)
            cursor = conn.cursor()
            query = """
            SELECT url, title, visit_count, last_visit_time
            FROM urls
            ORDER BY last_visit_time DESC
            """
            cursor.execute(query)
            browser_history = []
            for row in cursor.fetchall():
                url, title, visit_count, last_visit_time = row
                visit_count = visit_count or 0
                last_visit_time = datetime(1601, 1, 1) + timedelta(microseconds=last_visit_time)
                browser_history.append((url, title, visit_count, last_visit_time))
            cursor.close()
            conn.close()
            return browser_history
        except sqlite3.OperationalError as e:
            messagebox.showerror("Error", f"Error accessing {browser_name} history: {e}")
            return []

    def convert_to_hex(data):
        """Convert any data to its hexadecimal representation with space separation."""
        if isinstance(data, str):
            return ' '.join(binascii.hexlify(data.encode('utf-8')).decode('utf-8')[i:i+2] for i in range(0, len(data) * 2, 2))
        elif isinstance(data, int):
            return ' '.join(binascii.hexlify(str(data).encode('utf-8')).decode('utf-8')[i:i+2] for i in range(0, len(str(data)) * 2, 2))
        elif isinstance(data, datetime):
            return ' '.join(binascii.hexlify(data.isoformat().encode('utf-8')).decode('utf-8')[i:i+2] for i in range(0, len(data.isoformat()) * 2, 2))
        else:
            return ' '.join(binascii.hexlify(str(data).encode('utf-8')).decode('utf-8')[i:i+2] for i in range(0, len(str(data)) * 2, 2))

    def display_history(history, text_widget, hex_table_widget):
        """Display the fetched browser history in both human-readable format and hex format."""
        text_widget.delete(1.0, tk.END)
        hex_table_widget.delete(*hex_table_widget.get_children())
        if not history:
            text_widget.insert(tk.END, "No history data found.\n")
        else:
            text_widget.insert(tk.END, "--- Browser History ---\n\n")
            for url, title, visit_count, last_visit in history[:100]:
                text_widget.insert(tk.END, f"URL: {url}\nTitle: {title}\nVisits: {visit_count}\nLast Visited: {last_visit}\n\n")
                hex_url = convert_to_hex(url)
                hex_title = convert_to_hex(title)
                hex_visit_count = convert_to_hex(visit_count)
                hex_last_visit_time = convert_to_hex(last_visit)
                hex_table_widget.insert("", "end", values=(hex_url, hex_title, hex_visit_count, hex_last_visit_time))

    def get_encryption_key():
        """Retrieve the AES encryption key for Chrome passwords."""
        local_state_path = os.path.expanduser(r"~\\AppData\\Local\\Google\\Chrome\\User Data\\Local State")
        with open(local_state_path, "r", encoding="utf-8") as file:
            local_state = json.load(file)
        encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        decrypted_key = win32crypt.CryptUnprotectData(encrypted_key[5:], None, None, None, 0)[1]
        return decrypted_key

    def decrypt_password(password, key):
        """Decrypt AES-encrypted password."""
        try:
            iv = password[3:15]
            payload = password[15:-16]
            auth_tag = password[-16:]
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, auth_tag), backend=default_backend())
            decryptor = cipher.decryptor()
            return (decryptor.update(payload) + decryptor.finalize()).decode("utf-8")
        except Exception:
            return "Decryption failed"
        
    def fetch_file_meta(file_path):
        try:
            with open(file_path, "rb") as file:
                data = file.read(512)  # Read the first 512 bytes
                meta=""
                for i in range(0, len(data), 16):  # Display 16 bytes per line
                    hex_values = ' '.join(f"{byte:02x}" for byte in data[i:i+16])
                    ascii_values = ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in data[i:i+16])
                    meta+=(f"{i:04x}: {hex_values} {ascii_values}\n")
                return meta
        except FileNotFoundError:
            return FileNotFoundError
        except PermissionError:
            return PermissionError
        except Exception:
            return Exception
    
    def get_encryption_keyedge():
        """Retrieve the AES encryption key for Edge passwords stored in the 'Local State' file."""
        local_state_path = os.path.expanduser(r"~\\AppData\\Local\\Microsoft\\Edge\\User Data\\Local State")
        with open(local_state_path, "r", encoding="utf-8") as file:
            local_state = json.load(file)
        encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        encrypted_key = encrypted_key[5:]  # Remove "DPAPI" prefix
        decrypted_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
        return decrypted_key

    def fetch_edge_passwords(profile_name):
        """Fetch passwords for a given Edge profile."""
        edge_path = os.path.expanduser(rf"~\\AppData\\Local\\Microsoft\\Edge\\User Data\\{profile_name}\\Login Data")
        if not os.path.exists(edge_path):
            return []
        key = get_encryption_keyedge() 
        shutil.copy(edge_path, "tempLoginData")
        try:
            conn = sqlite3.connect("tempLoginData")
            cursor = conn.cursor()
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
            passwords = []
            for origin, username, encrypted_password in cursor.fetchall():
                if encrypted_password.startswith(b'v10'):
                    password = decrypt_password(encrypted_password, key)
                else:
                    password = win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1].decode()
                passwords.append((origin, username, password))
            conn.close()
            return passwords
        except sqlite3.OperationalError:
            return []

    def fetch_edge_passwords_and_display():
        selected_profile = edge_profile_combo.get()
        if not selected_profile:
            messagebox.showwarning("Warning", "Please select an Edge profile.")
            return
        passwords = fetch_edge_passwords(selected_profile)
        display_data(passwords, text_area, mode="passwords")

    def fetch_chrome_passwords(profile_name):
        """Fetch passwords for a given Chrome profile."""
        chrome_path = os.path.expanduser(rf"~\\AppData\\Local\\Google\\Chrome\\User Data\\{profile_name}\\Login Data")
        if not os.path.exists(chrome_path):
            return []
        key = get_encryption_key()
        shutil.copy(chrome_path, "tempLoginData")
        try:
            conn = sqlite3.connect("tempLoginData")
            cursor = conn.cursor()
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
            passwords = []
            for origin, username, encrypted_password in cursor.fetchall():
                if encrypted_password.startswith(b'v10'):
                    password = decrypt_password(encrypted_password, key)
                else:
                    password = win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1].decode()
                passwords.append((origin, username, password))
            conn.close()
            return passwords
        except sqlite3.OperationalError:
            return []

    def display_data(data, text_widget, mode):
        """Display fetched data in the text widget."""
        text_widget.delete(1.0, tk.END)
        if not data:
            text_widget.insert(tk.END, "No data found.\n")
        elif mode!="meta":
            for entry in data:
                if mode == "history":
                    url, title, visit_count, last_visit = entry
                    text_widget.insert(tk.END, f"URL: {url}\nTitle: {title}\nVisits: {visit_count}\nLast Visited: {last_visit}\n\n")
                elif mode == "passwords":
                    origin, username, password = entry
                    text_widget.insert(tk.END, f"Origin: {origin}\nUsername: {username}\nPassword: {password}\n\n")
        else:
            text_widget.insert(tk.END, data)

    
    def fetch_browser_bookmarks(browser_name, profile_name=None):
        """Fetch bookmarks for Chrome or Edge."""
        if browser_name == "Chrome":
            bookmark_path = os.path.expanduser(rf"~\AppData\Local\Google\Chrome\User Data\{profile_name}\Bookmarks")
        elif browser_name == "Edge":
            bookmark_path = os.path.expanduser(rf"~\AppData\Local\Microsoft\Edge\User Data\{profile_name}\Bookmarks")
        else:
            messagebox.showerror("Error", "Invalid browser name.")
            return []

        if not os.path.exists(bookmark_path):
            messagebox.showerror("Error", f"{browser_name} bookmarks file not found.")
            return []

        try:
            with open(bookmark_path, "r", encoding="utf-8") as file:
                bookmark_data = json.load(file)

            def extract_bookmarks(node):
                """Recursively extract bookmarks."""
                bookmarks = []
                if isinstance(node, dict):
                    if "type" in node and node["type"] == "url":
                        bookmarks.append((node.get("name", "Unknown"), node.get("url", "")))
                    if "children" in node:
                        for child in node["children"]:
                            bookmarks.extend(extract_bookmarks(child))
                elif isinstance(node, list):
                    for item in node:
                        bookmarks.extend(extract_bookmarks(item))
                return bookmarks

            roots = bookmark_data.get("roots", {})
            all_bookmarks = []
            for root_key, root_node in roots.items():
                all_bookmarks.extend(extract_bookmarks(root_node))
            return all_bookmarks

        except Exception as e:
            messagebox.showerror("Error", f"Error reading {browser_name} bookmarks: {e}")
            return []

    # Display bookmarks in the GUI
    def display_bookmarks(bookmarks, text_widget, hex_table_widget):
        """Display the fetched browser bookmarks."""
        text_widget.delete(1.0, tk.END)
        hex_table_widget.delete(*hex_table_widget.get_children())

        if not bookmarks:
            text_widget.insert(tk.END, "No bookmarks found.\n")
        else:
            text_widget.insert(tk.END, "--- Bookmarks ---\n\n")
            for name, url in bookmarks:
                text_widget.insert(tk.END, f"Name: {name}\nURL: {url}\n\n")

                hex_name = convert_to_hex(name)
                hex_url = convert_to_hex(url)
                hex_table_widget.insert("", "end", values=(hex_name, hex_url, "", ""))

    def main():
        def fetch_chrome_bookmarks_and_display():
            selected_profile = chrome_profile_combo.get()
            if not selected_profile:
                messagebox.showwarning("Warning", "Please select a Chrome profile.")
                return

            bookmarks = fetch_browser_bookmarks("Chrome", selected_profile)
            display_bookmarks(bookmarks, text_area, hex_table)

        def fetch_edge_bookmarks_and_display():
            selected_profile = edge_profile_combo.get()
            if not selected_profile:
                messagebox.showwarning("Warning", "Please select an Edge profile.")
                return

            bookmarks = fetch_browser_bookmarks("Edge", selected_profile)
            display_bookmarks(bookmarks, text_area, hex_table)

        def display_bookmarks(bookmarks, text_widget, hex_table_widget):
            """Display the fetched browser bookmarks."""
            text_widget.delete(1.0, tk.END)
            hex_table_widget.delete(*hex_table_widget.get_children())

            if not bookmarks:
                text_widget.insert(tk.END, "No bookmarks found.\n")
            else:
                text_widget.insert(tk.END, "--- Bookmarks ---\n\n")
                for name, url in bookmarks:
                    text_widget.insert(tk.END, f"Name: {name}\nURL: {url}\n\n")

                    hex_name = convert_to_hex(name)
                    hex_url = convert_to_hex(url)
                    hex_table_widget.insert("", "end", values=(hex_name, hex_url, "", ""))
        def fetch_chrome_passwords_and_display():
            selected_profile = chrome_profile_combo.get()
            if not selected_profile:
                messagebox.showwarning("Warning", "Please select a Chrome profile.")
                return
            passwords = fetch_chrome_passwords(selected_profile)
            display_data(passwords, text_area, mode="passwords")

        def fetch_chrome_history_and_display():
            selected_profile = chrome_profile_combo.get()
            if not selected_profile:
                messagebox.showwarning("Warning", "Please select a Chrome profile.")
                return
            history = fetch_browser_history("Chrome", selected_profile)
            display_history(history, text_area, hex_table)
            if os.path.exists("tempBrowserHist"):
                os.remove("tempBrowserHist")

        def fetch_edge_history_and_display():
            selected_profile = edge_profile_combo.get()
            if not selected_profile:
                messagebox.showwarning("Warning", "Please select an Edge profile.")
                return
            history = fetch_browser_history("Edge", selected_profile)
            display_history(history, text_area, hex_table)
            if os.path.exists("tempBrowserHist"):
                os.remove("tempBrowserHist")

        def fetch_edge_passwords_and_display():
            selected_profile = edge_profile_combo.get()
            if not selected_profile:
                messagebox.showwarning("Warning", "Please select an Edge profile.")
                return
            passwords = fetch_edge_passwords(selected_profile)
            display_data(passwords, text_area, mode="passwords")
        
        def display_edge_meta():
            selected_profile = edge_profile_combo.get()
            if not selected_profile:
                messagebox.showwarning("Warning", "Please select an Edge profile.")
                return
            meta_data=fetch_file_meta(os.path.expanduser("~\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\History"))
            display_data(meta_data,text_area,mode="meta")

        def display_chrome_meta():
            selected_profile = chrome_profile_combo.get()
            if not selected_profile:
                messagebox.showwarning("Warning", "Please select an Chrome profile.")
                return
            meta_data=fetch_file_meta(os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History"))
            display_data(meta_data,text_area,mode="meta")


        window = tk.Tk()
        window.title("Browser Data Fetcher")
        window.geometry("1360x768")
        window.configure(bg="#2e2e2e")  # Dark theme background

        style = ttk.Style()
        style.theme_use("clam")  # Apply a modern ttk theme
        style.configure("TNotebook", background="#2e2e2e", borderwidth=0)
        style.configure("TNotebook.Tab", background="#404040", foreground="white", padding=[10, 5], font=("Arial", 12))
        style.map("TNotebook.Tab", background=[("selected", "#007acc")], foreground=[("selected", "white")])

        style.configure("TFrame", background="#2e2e2e")
        style.configure("TLabel", background="#2e2e2e", foreground="white", font=("Arial", 11))
        style.configure("TButton", background="#007acc", foreground="white", padding=6, font=("Arial", 10, "bold"))
        style.map("TButton", background=[("active", "#005f99")])

        notebook = ttk.Notebook(window)
        notebook.pack(pady=10, fill="both", expand=True)

        # Chrome frame
        chrome_frame = ttk.Frame(notebook)
        chrome_frame.pack(fill="both", expand=True)
        notebook.add(chrome_frame, text="Chrome")

        chrome_label = ttk.Label(chrome_frame, text="Select Chrome Profile:")
        chrome_label.pack(pady=5)
        chrome_profile_combo = ttk.Combobox(chrome_frame, values=get_chrome_profiles(), state="readonly")
        chrome_profile_combo.pack(pady=5)
        chrome_history_button = ttk.Button(chrome_frame, text="Fetch History", command=fetch_chrome_history_and_display)
        chrome_history_button.pack(pady=10)
        chrome_password_button = ttk.Button(chrome_frame, text="Fetch Passwords", command=fetch_chrome_passwords_and_display)
        chrome_password_button.pack(pady=5)
        chrome_bookmarks_button = ttk.Button(chrome_frame, text="Fetch Bookmarks", command=fetch_chrome_bookmarks_and_display)
        chrome_bookmarks_button.pack(pady=5)
        chrome_meta_button = ttk.Button(chrome_frame, text="History Database Metadata", command=display_chrome_meta)
        chrome_meta_button.pack(pady=10)

        # Edge frame
        edge_frame = ttk.Frame(notebook)
        edge_frame.pack(fill="both", expand=True)
        notebook.add(edge_frame, text="Edge")

        def open_notepad_viewer():
            window.destroy()
            open_notepad_viewer_window()

        edge_label = ttk.Label(edge_frame, text="Select Edge Profile:")
        edge_label.pack(pady=5)
        edge_profile_combo = ttk.Combobox(edge_frame, values=get_edge_profiles(), state="readonly")
        edge_profile_combo.pack(pady=5)
        edge_history_button = ttk.Button(edge_frame, text="Fetch History", command=fetch_edge_history_and_display)
        edge_history_button.pack(pady=10)
        edge_password_button = ttk.Button(edge_frame, text="Fetch Passwords", command=fetch_edge_passwords_and_display)
        edge_password_button.pack(pady=5)
        edge_bookmarks_button = ttk.Button(edge_frame, text="Fetch Bookmarks", command=fetch_edge_bookmarks_and_display)
        edge_bookmarks_button.pack(pady=5)
        edge_meta_button = ttk.Button(edge_frame, text="History Database Metadata", command=display_edge_meta)
        edge_meta_button.pack(pady=10)
        placeholder_button = ttk.Button(window, text="Notepad Viewer", command=open_notepad_viewer)
        placeholder_button.pack(pady=10)


        # Text area
        text_area = scrolledtext.ScrolledText(window, wrap=tk.WORD, height=15, width=100, bg="#404040", fg="white", font=("Arial", 10))
        text_area.pack(pady=20)

        # Hex table
        hex_table = ttk.Treeview(window, columns=("col1", "col2", "col3", "col4"), show="headings")
        hex_table.heading("col1", text="URL")
        hex_table.heading("col2", text="Title")
        hex_table.heading("col3", text="Visit Count")
        hex_table.heading("col4", text="Last Visit")
        hex_table.pack(pady=20)

        



    main()

if __name__ == "__main__":
    show_main_menu()
