import customtkinter as ctk
from tkinter import *
from tkinter import messagebox
import json
import os
from cryptography.fernet import Fernet
import base64
import pyperclip
import sys

# --- Costanti ---
PASSWORDS_FILE = 'passwords.json'

# --- Temi e Colori ---
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class PasswordManager:
    def __init__(self, master_password):
        self.key = self._derive_key(master_password)
        self.fernet = Fernet(self.key)

    def _derive_key(self, password):
        password = password.ljust(32)[:32].encode()
        return base64.urlsafe_b64encode(password)

    def encrypt(self, data):
        return self.fernet.encrypt(json.dumps(data).encode())

    def decrypt(self, encrypted_data):
        try:
            decrypted = self.fernet.decrypt(encrypted_data)
            return json.loads(decrypted.decode())
        except Exception as e:
            print(f"Errore nella decrittazione: {e}")
            return None

def save_passwords(passwords, master_password):
    try:
        pm = PasswordManager(master_password)
        encrypted = pm.encrypt(passwords)
        with open(PASSWORDS_FILE, 'wb') as f:
            f.write(encrypted)
        return True
    except Exception as e:
        print(f"Errore nel salvataggio: {e}")
        return False

def load_passwords(master_password):
    if not os.path.exists(PASSWORDS_FILE):
        return {}

    try:
        with open(PASSWORDS_FILE, 'rb') as f:
            encrypted = f.read()

        if not encrypted:
            return {}

        pm = PasswordManager(master_password)
        decrypted = pm.decrypt(encrypted)

        if decrypted is None:
            raise ValueError("Decrittazione fallita")

        return decrypted
    except Exception as e:
        print(f"Errore nel caricamento: {e}")
        return None

def validate_master_password(master_password):
    if not master_password:
        return False

    try:
        if not os.path.exists(PASSWORDS_FILE):
            test_data = {"_test": "test"}
            if not save_passwords(test_data, master_password):
                return False

        decrypted_data = load_passwords(master_password)


        if decrypted_data is None:
            return False


        if not isinstance(decrypted_data, dict):
            return False

        return True
    except Exception as e:
        print(f"Errore di validazione: {e}")
        return False

class PasswordEntry(ctk.CTkEntry):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.is_password_visible = False

    def toggle_visibility(self):
        self.is_password_visible = not self.is_password_visible
        if self.is_password_visible:
            self.configure(show="")
        else:
            self.configure(show="•")

class PasswordCard(ctk.CTkFrame):
    def __init__(self, master, site, username, password, on_delete=None, on_edit=None, **kwargs):
        super().__init__(master, **kwargs)


        self.configure(fg_color=("gray85", "gray25"))
        self.site = site


        main_layout = ctk.CTkFrame(self, fg_color="transparent")
        main_layout.pack(fill="both", expand=True, padx=10, pady=10)


        info_frame = ctk.CTkFrame(main_layout, fg_color="transparent")
        info_frame.pack(side="left", fill="both", expand=True)


        self.site_label = ctk.CTkLabel(
            info_frame,
            text=site,
            font=("Helvetica", 18, "bold"),
            anchor="w"
        )
        self.site_label.pack(fill="x", pady=(0, 5))


        username_frame = ctk.CTkFrame(info_frame, fg_color="transparent")
        username_frame.pack(fill="x")

        ctk.CTkLabel(
            username_frame,
            text="👤",
            font=("Helvetica", 14),
            width=25
        ).pack(side="left")

        self.username_label = ctk.CTkLabel(
            username_frame,
            text=username,
            font=("Helvetica", 14),
            anchor="w"
        )
        self.username_label.pack(side="left", fill="x", expand=True)


        password_frame = ctk.CTkFrame(info_frame, fg_color="transparent")
        password_frame.pack(fill="x")

        ctk.CTkLabel(
            password_frame,
            text="🔑",
            font=("Helvetica", 14),
            width=25
        ).pack(side="left")

        self.password_var = StringVar(value="•" * len(password))
        self.password_label = ctk.CTkLabel(
            password_frame,
            textvariable=self.password_var,
            font=("Helvetica", 14),
            anchor="w"
        )
        self.password_label.pack(side="left", fill="x", expand=True)


        button_frame = ctk.CTkFrame(main_layout, fg_color="transparent")
        button_frame.pack(side="right", padx=(10, 0))


        button_style = {
            "width": 35,
            "height": 35,
            "corner_radius": 8,
            "font": ("Helvetica", 16)
        }

        self.view_btn = ctk.CTkButton(
            button_frame,
            text="👁",
            command=lambda: self.toggle_password(password),
            **button_style
        )
        self.view_btn.pack(side="left", padx=2)

        self.copy_user_btn = ctk.CTkButton(
            button_frame,
            text="📋",
            command=lambda: self.copy_to_clipboard(username, "Username"),
            **button_style
        )
        self.copy_user_btn.pack(side="left", padx=2)

        self.copy_pass_btn = ctk.CTkButton(
            button_frame,
            text="🔒",
            command=lambda: self.copy_to_clipboard(password, "Password"),
            **button_style
        )
        self.copy_pass_btn.pack(side="left", padx=2)

        if on_edit:
            self.edit_btn = ctk.CTkButton(
                button_frame,
                text="✏️",
                command=lambda: on_edit(site),
                **button_style
            )
            self.edit_btn.pack(side="left", padx=2)

        if on_delete:
            self.delete_btn = ctk.CTkButton(
                button_frame,
                text="🗑️",
                command=lambda: on_delete(site),
                **button_style
            )
            self.delete_btn.pack(side="left", padx=2)

        # Effetti hover
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)

    def toggle_password(self, password):
        current_text = self.password_var.get()
        is_hidden = all(c == "•" for c in current_text)

        if is_hidden:
            self.password_var.set(password)
            self.view_btn.configure(fg_color="green")
        else:
            self.password_var.set("•" * len(password))
            self.view_btn.configure(fg_color=None)

    def copy_to_clipboard(self, text, what="Testo"):
        pyperclip.copy(text)
        messagebox.showinfo("Copiato", f"{what} copiato negli appunti!")

    def on_enter(self, event):
        self.configure(fg_color=("gray75", "gray35"))

    def on_leave(self, event):
        self.configure(fg_color=("gray85", "gray25"))

class PasswordManagerApp:
    def __init__(self, master_password):
        self.master_password = master_password
        self.passwords = load_passwords(master_password) or {}  # Se None, usa {}

        self.window = ctk.CTk()
        self.window.title('Password Manager')
        self.window.geometry('1000x700')
        self.setup_ui()

    def setup_ui(self):

        header = ctk.CTkFrame(self.window, fg_color="transparent")
        header.pack(fill="x", padx=30, pady=15)

        title = ctk.CTkLabel(header, text="Password Manager", font=("Helvetica", 32, "bold"))
        title.pack(side="left")


        toolbar = ctk.CTkFrame(self.window, fg_color="transparent")
        toolbar.pack(fill="x", padx=30, pady=15)

        button_style = {"height": 40, "font": ("Helvetica", 14)}

        add_btn = ctk.CTkButton(toolbar, text="+ Nuova Password",
                               command=self.add_password, **button_style)
        add_btn.pack(side="left", padx=5)

        change_master_btn = ctk.CTkButton(toolbar, text="🔒 Cambia Master Password",
                                        command=self.change_master_password, **button_style)
        change_master_btn.pack(side="right", padx=5)

        self.scroll_frame = ctk.CTkScrollableFrame(self.window)
        self.scroll_frame.pack(fill="both", expand=True, padx=30, pady=15)

        self.refresh_passwords()

    def refresh_passwords(self):

        for widget in self.scroll_frame.winfo_children():
            widget.destroy()


        try:
            for site, info in self.passwords.items():
                if isinstance(info, dict) and 'username' in info and 'password' in info:
                    card = PasswordCard(
                        self.scroll_frame,
                        site=site,
                        username=info['username'],
                        password=info['password'],
                        on_delete=self.delete_password,
                        on_edit=self.edit_password
                    )
                    card.pack(fill="x", padx=5, pady=5)
        except Exception as e:
            print(f"Errore nel refresh delle password: {e}")
            messagebox.showerror("Errore", "Errore nel caricamento delle password")

    def add_password(self):
        dialog = ctk.CTkToplevel(self.window)
        dialog.title("Aggiungi Password")
        dialog.geometry("400x300")
        dialog.grab_set()

        ctk.CTkLabel(dialog, text="Nuovo Account", font=("Helvetica", 20, "bold")).pack(pady=10)

        site_entry = ctk.CTkEntry(dialog, placeholder_text="Sito")
        site_entry.pack(fill="x", padx=20, pady=5)

        username_entry = ctk.CTkEntry(dialog, placeholder_text="Username")
        username_entry.pack(fill="x", padx=20, pady=5)

        password_entry = PasswordEntry(dialog, placeholder_text="Password", show="•")
        password_entry.pack(fill="x", padx=20, pady=5)

        show_pass_btn = ctk.CTkButton(dialog, text="👁 Mostra/Nascondi",
                                     command=password_entry.toggle_visibility)
        show_pass_btn.pack(pady=5)

        def save():
            site = site_entry.get()
            username = username_entry.get()
            password = password_entry.get()

            if not all([site, username, password]):
                messagebox.showwarning("Errore", "Tutti i campi sono obbligatori!")
                return

            self.passwords[site] = {'username': username, 'password': password}
            save_passwords(self.passwords, self.master_password)
            self.refresh_passwords()
            dialog.destroy()

        ctk.CTkButton(dialog, text="Salva", command=save).pack(pady=20)

    def edit_password(self, site):
        info = self.passwords[site]
        dialog = ctk.CTkToplevel(self.window)
        dialog.title("Modifica Password")
        dialog.geometry("400x300")
        dialog.grab_set()

        ctk.CTkLabel(dialog, text=f"Modifica {site}", font=("Helvetica", 20, "bold")).pack(pady=10)

        username_entry = ctk.CTkEntry(dialog, placeholder_text="Username")
        username_entry.insert(0, info['username'])
        username_entry.pack(fill="x", padx=20, pady=5)

        password_entry = PasswordEntry(dialog, placeholder_text="Password", show="•")
        password_entry.insert(0, info['password'])
        password_entry.pack(fill="x", padx=20, pady=5)

        show_pass_btn = ctk.CTkButton(dialog, text="👁 Mostra/Nascondi",
                                     command=password_entry.toggle_visibility)
        show_pass_btn.pack(pady=5)

        def save():
            username = username_entry.get()
            password = password_entry.get()

            if not all([username, password]):
                messagebox.showwarning("Errore", "Tutti i campi sono obbligatori!")
                return

            self.passwords[site] = {'username': username, 'password': password}
            save_passwords(self.passwords, self.master_password)
            self.refresh_passwords()
            dialog.destroy()

        ctk.CTkButton(dialog, text="Salva", command=save).pack(pady=20)

    def delete_password(self, site):
        if messagebox.askyesno("Conferma", f"Vuoi davvero eliminare {site}?"):
            del self.passwords[site]
            save_passwords(self.passwords, self.master_password)
            self.refresh_passwords()

    def change_master_password(self):
        dialog = ctk.CTkToplevel(self.window)
        dialog.title("Cambia Master Password")
        dialog.geometry("400x300")
        dialog.grab_set()

        ctk.CTkLabel(dialog, text="Cambia Master Password",
                     font=("Helvetica", 20, "bold")).pack(pady=10)

        old_pass = ctk.CTkEntry(dialog, placeholder_text="Password Attuale", show="•")
        old_pass.pack(fill="x", padx=20, pady=5)

        new_pass = ctk.CTkEntry(dialog, placeholder_text="Nuova Password", show="•")
        new_pass.pack(fill="x", padx=20, pady=5)

        confirm_pass = ctk.CTkEntry(dialog, placeholder_text="Conferma Password", show="•")
        confirm_pass.pack(fill="x", padx=20, pady=5)

        def change():
            if old_pass.get() != self.master_password:
                messagebox.showerror("Errore", "Password attuale errata!")
                return

            if new_pass.get() != confirm_pass.get():
                messagebox.showerror("Errore", "Le password non coincidono!")
                return

            if len(new_pass.get()) < 1:
                messagebox.showerror("Errore", "La password non può essere vuota!")
                return

            try:
                if save_passwords(self.passwords, new_pass.get()):
                    self.master_password = new_pass.get()
                    self.passwords = load_passwords(new_pass.get())
                    messagebox.showinfo("Successo", "Master password cambiata!")
                    dialog.destroy()
                else:
                    messagebox.showerror("Errore", "Errore nel salvataggio della nuova password")
            except Exception as e:
                messagebox.showerror("Errore", f"Errore nel cambio password: {str(e)}")


        ctk.CTkButton(dialog, text="Cambia Password",
                     command=change).pack(pady=20)

    def run(self):
        self.window.mainloop()

def main():
    root = ctk.CTk()
    root.withdraw()

    max_attempts = 3
    attempts = 0

    while attempts < max_attempts:
        dialog = ctk.CTkInputDialog(
            title="Master Password",
            text=f"Inserisci la master password: (tentativo {attempts + 1}/{max_attempts})"
        )
        master_password = dialog.get_input()

        if master_password is None:
            sys.exit()

        if validate_master_password(master_password):

            passwords = load_passwords(master_password)
            if passwords is None:
                messagebox.showerror("Errore", "Password non valida!")
                attempts += 1
                continue

            try:
                app = PasswordManagerApp(master_password)
                app.run()
                break
            except Exception as e:
                messagebox.showerror("Errore", f"Errore nell'avvio dell'applicazione: {str(e)}")
                sys.exit()
        else:
            attempts += 1
            if attempts < max_attempts:
                messagebox.showerror("Errore",
                    f"Password non valida! Hai ancora {max_attempts - attempts} tentativi.")
            else:
                messagebox.showerror("Errore",
                    "Numero massimo di tentativi raggiunto. L'applicazione verrà chiusa.")
                sys.exit()

if __name__ == '__main__':
    main()
