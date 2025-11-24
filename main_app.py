import sys
import os
from base64 import urlsafe_b64encode, urlsafe_b64decode

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QWidget, QPushButton,
    QLabel, QLineEdit, QListWidget, QListWidgetItem, QMessageBox,
    QHBoxLayout, QDialog, QFormLayout, QDialogButtonBox, QTextEdit,
    QInputDialog, QSplitter, QSizePolicy
)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QIcon, QClipboard

from PIL import Image
from io import BytesIO

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Modules
from db_manager import DatabaseManager
from crypto_utils import derive_key, generate_salt, encrypt_data, decrypt_data
from totp_utils import generate_totp_secret, get_totp_uri, generate_qr_code, verify_totp

# 🔵 DeepFace biometric authenticator
from biometric_auth import BiometricAuthenticator



# -------------------------------------------------------------
#   PASSWORD ENTRY DIALOG - unchanged
# -------------------------------------------------------------
class PasswordEntryDialog(QDialog):
    def __init__(self, parent=None, credential_data=None):
        super().__init__(parent)
        self.setWindowTitle("Add / Edit Credential")
        self.setFixedSize(480, 360)

        self.layout = QFormLayout()
        self.service_input = QLineEdit()
        self.username_input = QLineEdit()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.notes_input = QTextEdit()
        self.notes_input.setMinimumHeight(80)

        self.layout.addRow("Service Name:", self.service_input)
        self.layout.addRow("Username:", self.username_input)
        self.layout.addRow("Password:", self.password_input)
        self.layout.addRow("Notes:", self.notes_input)

        self.buttonBox = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.buttonBox.accepted.connect(self.accept)
        self.buttonBox.rejected.connect(self.reject)

        self.layout.addRow(self.buttonBox)
        self.setLayout(self.layout)

        self.credential_id = None
        if credential_data:
            self.credential_id = credential_data.get("id")
            self.service_input.setText(credential_data.get("service_name", ""))
            self.username_input.setText(credential_data.get("username", ""))
            self.password_input.setText(credential_data.get("password", ""))
            self.notes_input.setText(credential_data.get("notes", ""))



# -------------------------------------------------------------
#   SETUP VAULT DIALOG (Master Password + TOTP + Face)
# -------------------------------------------------------------
class SetupVaultDialog(QDialog):
    def __init__(self, parent=None, db_manager=None):
        super().__init__(parent)
        self.db_manager = db_manager
        self.setWindowTitle("Setup Vault")
        self.setFixedSize(480, 560)

        self.layout = QVBoxLayout()
        self.setLayout(self.layout)

        self.info_label = QLabel(
            "Create a strong master password.\n"
            "Configure TOTP.\n"
            "Then your FACE will be registered with DeepFace (mandatory)."
        )
        self.info_label.setWordWrap(True)
        self.layout.addWidget(self.info_label)

        form = QFormLayout()
        self.master_password_input = QLineEdit()
        self.master_password_input.setEchoMode(QLineEdit.Password)
        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setEchoMode(QLineEdit.Password)

        form.addRow("Master Password:", self.master_password_input)
        form.addRow("Confirm Password:", self.confirm_password_input)
        self.layout.addLayout(form)

        self.totp_secret = generate_totp_secret()
        self.totp_uri = get_totp_uri(self.totp_secret, "VaultUser", "BiometricPasswordVault")
        qr_img = generate_qr_code(self.totp_uri)

        self.qr_label = QLabel()
        self.qr_label.setFixedSize(260, 260)
        self.qr_label.setAlignment(Qt.AlignCenter)
        self.set_qr_image(qr_img)
        self.layout.addWidget(self.qr_label)

        self.totp_input = QLineEdit()
        self.totp_input.setPlaceholderText("Enter 2FA code")
        self.layout.addWidget(self.totp_input)

        self.buttonBox = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.buttonBox.accepted.connect(self.on_accept)
        self.buttonBox.rejected.connect(self.reject)
        self.layout.addWidget(self.buttonBox)

        self.salt = generate_salt()
        self.master_key = None
        self.master_password_hash_for_verification = None

    def set_qr_image(self, img: Image.Image):
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        from PyQt5.QtGui import QPixmap
        pix = QPixmap()
        pix.loadFromData(buffer.getvalue())
        self.qr_label.setPixmap(pix.scaled(260, 260, Qt.KeepAspectRatio))

    def on_accept(self):
        pw = self.master_password_input.text()
        pw2 = self.confirm_password_input.text()

        if pw != pw2 or len(pw) < 8:
            QMessageBox.warning(self, "Error", "Passwords do not match or too short.")
            return

        if not verify_totp(self.totp_secret, self.totp_input.text().strip()):
            QMessageBox.warning(self, "Error", "Invalid TOTP code.")
            return

        # Derive key + hash
        self.master_key = derive_key(pw, self.salt)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=310000,
            backend=default_backend()
        )
        self.master_password_hash_for_verification = kdf.derive(pw.encode())

        # 🔵 Mandatory Biometric Setup (DeepFace)
        biometric = BiometricAuthenticator(self, self.db_manager)
        if not biometric.register_face():
            QMessageBox.critical(self, "Biometric Error", "Face registration failed.")
            return

        self.accept()



# -------------------------------------------------------------
#   UNLOCK VAULT DIALOG (Biometric or Password+TOTP)
# -------------------------------------------------------------
class UnlockVaultDialog(QDialog):
    def __init__(self, db_manager: DatabaseManager, parent=None):
        super().__init__(parent)
        self.db_manager = db_manager
        self.setWindowTitle("Unlock Vault")
        self.setFixedSize(420, 360)

        self.biometric_auth = BiometricAuthenticator(self, self.db_manager)
        self.master_key = None
        self.used_biometric = False

        self.layout = QVBoxLayout()
        self.setLayout(self.layout)

        # Biometric
        self.layout.addWidget(QLabel("<b>Unlock with Facial Recognition:</b>"))
        bio_btn = QPushButton("Use Face Unlock")
        bio_btn.clicked.connect(self._biometric_unlock)
        self.layout.addWidget(bio_btn)

        self.layout.addWidget(QLabel("<hr>"))

        # Password fallback
        self.layout.addWidget(QLabel("<b>Unlock with Password + TOTP:</b>"))
        form = QFormLayout()
        self.master_password_input = QLineEdit()
        self.master_password_input.setEchoMode(QLineEdit.Password)
        self.totp_input = QLineEdit()
        form.addRow("Master Password:", self.master_password_input)
        form.addRow("TOTP Code:", self.totp_input)
        self.layout.addLayout(form)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.accepted.connect(self._password_unlock)
        btns.rejected.connect(self.reject)
        self.layout.addWidget(btns)

    def _biometric_unlock(self):
        if self.biometric_auth.authenticate():
            self.used_biometric = True
            self.master_key = b"biometric_placeholder_key"
            self.accept()

    def _password_unlock(self):
        pw = self.master_password_input.text().strip()
        totp = self.totp_input.text().strip()

        if not pw or not totp:
            QMessageBox.warning(self, "Error", "Password and TOTP required.")
            return

        salt = urlsafe_b64decode(self.db_manager.get_config("salt"))
        candidate_key = derive_key(pw, salt)

        stored_hash = urlsafe_b64decode(self.db_manager.get_config("master_password_hash_for_verification"))

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=310000,
            backend=default_backend()
        )
        current_hash = kdf.derive(pw.encode())

        if current_hash != stored_hash:
            QMessageBox.warning(self, "Error", "Invalid master password.")
            return

        enc_secret = urlsafe_b64decode(self.db_manager.get_config("encrypted_totp_secret"))
        enc_iv = urlsafe_b64decode(self.db_manager.get_config("encrypted_totp_iv"))
        enc_tag = urlsafe_b64decode(self.db_manager.get_config("encrypted_totp_tag"))
        secret = decrypt_data(enc_secret, enc_iv, enc_tag, candidate_key).decode()

        if not verify_totp(secret, totp):
            QMessageBox.warning(self, "Error", "Invalid TOTP code.")
            return

        self.master_key = candidate_key
        self.accept()



# -------------------------------------------------------------
#   MAIN VAULT APP (mostly untouched)
# -------------------------------------------------------------
class PasswordVaultApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Biometric Password Vault")
        self.setMinimumSize(1000, 650)

        self.db = DatabaseManager()
        self.encryption_key = None
        self.is_configured = False

        self.check_configuration()

        # Setup vault if needed
        if not self.is_configured:
            setup = SetupVaultDialog(self, self.db)
            if setup.exec_() != QDialog.Accepted:
                QMessageBox.information(self, "Exit", "Vault setup incomplete.")
                sys.exit(0)

            self.encryption_key = setup.master_key

            self.db.save_config("salt", urlsafe_b64encode(setup.salt))
            self.db.save_config("master_password_hash_for_verification",
                                urlsafe_b64encode(setup.master_password_hash_for_verification))

            ciphertext, iv, tag = encrypt_data(
                setup.totp_secret.encode("utf-8"), self.encryption_key
            )
            self.db.save_config("encrypted_totp_secret", urlsafe_b64encode(ciphertext))
            self.db.save_config("encrypted_totp_iv", urlsafe_b64encode(iv))
            self.db.save_config("encrypted_totp_tag", urlsafe_b64encode(tag))

            self.is_configured = True

        # Unlock vault
        if not self.unlock_vault():
            QMessageBox.information(self, "Exit", "Failed to unlock vault.")
            sys.exit(0)

        # Build UI & load credentials
        self.init_ui()
        self.load_credentials()

        # Inactivity lock
        self.inactivity_timer = QTimer(self)
        self.inactivity_timer.setInterval(10 * 60 * 1000)
        self.inactivity_timer.timeout.connect(self.lock_vault)
        self.inactivity_timer.start()
        self.installEventFilter(self)

    def eventFilter(self, obj, event):
        if self.encryption_key and event.type() in (
            event.KeyPress, event.MouseMove, event.MouseButtonPress
        ):
            self.inactivity_timer.start()
        return super().eventFilter(obj, event)

    def check_configuration(self):
        if self.db.get_config("salt"):
            self.is_configured = True

    def unlock_vault(self):
        dialog = UnlockVaultDialog(self.db, self)
        if dialog.exec_() != QDialog.Accepted:
            return False

        if dialog.used_biometric:
            pw, ok = QInputDialog.getText(
                self, "Biometric Unlock",
                "Enter master password to derive encryption key:",
                QLineEdit.Password
            )
            if not ok or not pw:
                return False

            salt = urlsafe_b64decode(self.db.get_config("salt"))
            self.encryption_key = derive_key(pw, salt)
            return True

        self.encryption_key = dialog.master_key
        return True

    
    def init_ui(self):
        # Main layout: splitter with list and details/actions
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout()
        central.setLayout(main_layout)

        splitter = QSplitter(Qt.Horizontal)
        main_layout.addWidget(splitter)

        # Left: list of services
        left_widget = QWidget()
        left_layout = QVBoxLayout()
        left_widget.setLayout(left_layout)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search services...")
        self.search_input.textChanged.connect(self.filter_list)
        left_layout.addWidget(self.search_input)

        self.list_widget = QListWidget()
        self.list_widget.itemSelectionChanged.connect(self.on_selection_changed)
        left_layout.addWidget(self.list_widget)

        # Buttons under list
        list_btn_layout = QHBoxLayout()
        self.add_btn = QPushButton("Add")
        self.add_btn.clicked.connect(self.add_credential)
        self.edit_btn = QPushButton("Edit")
        self.edit_btn.clicked.connect(self.edit_credential)
        self.del_btn = QPushButton("Delete")
        self.del_btn.clicked.connect(self.delete_credential)
        list_btn_layout.addWidget(self.add_btn)
        list_btn_layout.addWidget(self.edit_btn)
        list_btn_layout.addWidget(self.del_btn)
        left_layout.addLayout(list_btn_layout)

        splitter.addWidget(left_widget)
        left_widget.setMinimumWidth(360)

        # Right: details and controls
        right_widget = QWidget()
        right_layout = QVBoxLayout()
        right_widget.setLayout(right_layout)

        self.service_label = QLabel("<b>Service:</b> -")
        self.username_label = QLabel("<b>Username:</b> -")
        self.password_label = QLabel("<b>Password:</b> -")
        self.notes_label = QLabel("<b>Notes:</b>\n-")
        self.password_masked = True

        right_layout.addWidget(self.service_label)
        right_layout.addWidget(self.username_label)
        right_layout.addWidget(self.password_label)

        pw_btn_layout = QHBoxLayout()
        self.reveal_btn = QPushButton("Reveal")
        self.reveal_btn.clicked.connect(self.reveal_password)
        self.copy_btn = QPushButton("Copy Password")
        self.copy_btn.clicked.connect(self.copy_password)
        pw_btn_layout.addWidget(self.reveal_btn)
        pw_btn_layout.addWidget(self.copy_btn)
        right_layout.addLayout(pw_btn_layout)

        right_layout.addWidget(self.notes_label)
        right_layout.addStretch()

        # Bottom controls
        bottom_btn_layout = QHBoxLayout()
        self.lock_btn = QPushButton("Lock Vault")
        self.lock_btn.clicked.connect(self.lock_vault)
        bottom_btn_layout.addWidget(self.lock_btn)
        right_layout.addLayout(bottom_btn_layout)

        splitter.addWidget(right_widget)

    def filter_list(self, text):
        text = text.strip().lower()
        for i in range(self.list_widget.count()):
            item = self.list_widget.item(i)
            item.setHidden(text and text not in item.text().lower())

    def load_credentials(self):
        """Load credentials from DB and populate list widget."""
        self.list_widget.clear()
        rows = self.db.get_credentials()
        # rows: id, service_name, username, encrypted_password, iv, tag, notes
        self._loaded_items = []  # store dicts for quick access
        for row in rows:
            try:
                cred_id, service, username, enc_pw_b64, iv_b64, tag_b64, notes = row
                # decrypt password using current encryption_key
                password_plain = "<decryption failed>"
                try:
                    enc_pw = urlsafe_b64decode(enc_pw_b64)
                    iv = urlsafe_b64decode(iv_b64)
                    tag = urlsafe_b64decode(tag_b64)
                    password_plain = decrypt_data(enc_pw, iv, tag, self.encryption_key).decode("utf-8")
                except Exception:
                    password_plain = "<cannot decrypt>"

                item_text = f"{service} ({username})"
                w_item = QListWidgetItem(item_text)
                self.list_widget.addItem(w_item)

                self._loaded_items.append({
                    "id": cred_id,
                    "service_name": service,
                    "username": username,
                    "password": password_plain,
                    "notes": notes or ""
                })
            except Exception as e:
                # skip faulty rows but continue loading others
                print(f"Error loading credential row: {e}")

        # Reset detail view
        self.clear_details()

    def clear_details(self):
        self.service_label.setText("<b>Service:</b> -")
        self.username_label.setText("<b>Username:</b> -")
        self.password_label.setText("<b>Password:</b> -")
        self.notes_label.setText("<b>Notes:</b>\n-")
        self.password_masked = True

    def on_selection_changed(self):
        idx = self.list_widget.currentRow()
        if idx < 0 or idx >= len(self._loaded_items):
            self.clear_details()
            return
        entry = self._loaded_items[idx]
        self.service_label.setText(f"<b>Service:</b> {entry['service_name']}")
        self.username_label.setText(f"<b>Username:</b> {entry['username']}")
        masked = "*" * 8 if entry["password"] and entry["password"] != "<cannot decrypt>" else entry["password"]
        self.password_label.setText(f"<b>Password:</b> {masked}")
        self.notes_label.setText(f"<b>Notes:</b>\n{entry['notes']}")
        self.password_masked = True

    def reveal_password(self):
        idx = self.list_widget.currentRow()
        if idx < 0 or idx >= len(self._loaded_items):
            return
        entry = self._loaded_items[idx]
        if entry["password"] in (None, "", "<cannot decrypt>", "<decryption failed>"):
            QMessageBox.warning(self, "Reveal Error", "Password unavailable or decryption failed.")
            return
        # toggle reveal/mask
        if self.password_masked:
            self.password_label.setText(f"<b>Password:</b> {entry['password']}")
            self.password_masked = False
            self.reveal_btn.setText("Hide")
        else:
            self.password_label.setText("<b>Password:</b> " + "*" * 8)
            self.password_masked = True
            self.reveal_btn.setText("Reveal")

    def copy_password(self):
        idx = self.list_widget.currentRow()
        if idx < 0 or idx >= len(self._loaded_items):
            return
        entry = self._loaded_items[idx]
        pw = entry.get("password")
        if not pw or pw in ("<cannot decrypt>", "<decryption failed>"):
            QMessageBox.warning(self, "Copy Error", "Password unavailable.")
            return
        clipboard: QClipboard = QApplication.clipboard()
        clipboard.setText(pw)
        QMessageBox.information(self, "Copied", "Password copied to clipboard (clear it after use).")

    def add_credential(self):
        dialog = PasswordEntryDialog(self)
        if dialog.exec_() != QDialog.Accepted:
            return
        service = dialog.service_input.text().strip()
        username = dialog.username_input.text().strip()
        password = dialog.password_input.text()
        notes = dialog.notes_input.toPlainText().strip()

        if not service or not username or not password:
            QMessageBox.warning(self, "Input Error", "Service, username, and password are required.")
            return

        try:
            ciphertext, iv, tag = encrypt_data(password.encode("utf-8"), self.encryption_key)
            saved = self.db.save_credential(service, username, ciphertext, iv, tag, notes)
            if not saved:
                QMessageBox.critical(self, "Save Error", "Failed to save credential.")
                return
            QMessageBox.information(self, "Saved", "Credential saved successfully.")
            self.load_credentials()
        except Exception as e:
            QMessageBox.critical(self, "Encryption Error", f"Failed to encrypt or save credential: {e}")

    def edit_credential(self):
        idx = self.list_widget.currentRow()
        if idx < 0 or idx >= len(self._loaded_items):
            QMessageBox.warning(self, "Select Entry", "Select an entry to edit.")
            return
        entry = self._loaded_items[idx]
        dialog = PasswordEntryDialog(self, {
            "id": entry["id"],
            "service_name": entry["service_name"],
            "username": entry["username"],
            "password": entry["password"] if entry["password"] not in ("<cannot decrypt>", "<decryption failed>") else "",
            "notes": entry["notes"]
        })
        if dialog.exec_() != QDialog.Accepted:
            return

        service = dialog.service_input.text().strip()
        username = dialog.username_input.text().strip()
        password = dialog.password_input.text()
        notes = dialog.notes_input.toPlainText().strip()

        # If password left blank, keep existing (if available). Otherwise encrypt new.
        try:
            if password:
                ciphertext, iv, tag = encrypt_data(password.encode("utf-8"), self.encryption_key)
            else:
                # Retrieve existing encrypted blobs from DB to re-save unchanged
                rows = self.db.get_credentials()
                # find the matching id row
                raw_row = next((r for r in rows if r[0] == entry["id"]), None)
                if not raw_row:
                    QMessageBox.critical(self, "Edit Error", "Original credential not found.")
                    return
                _, _, _, enc_pw_b64, iv_b64, tag_b64, _ = raw_row
                ciphertext = urlsafe_b64decode(enc_pw_b64)
                iv = urlsafe_b64decode(iv_b64)
                tag = urlsafe_b64decode(tag_b64)
            success = self.db.update_credential(entry["id"], service, username, ciphertext, iv, tag, notes)
            if not success:
                QMessageBox.critical(self, "Update Error", "Failed to update credential.")
                return
            QMessageBox.information(self, "Updated", "Credential updated successfully.")
            self.load_credentials()
        except Exception as e:
            QMessageBox.critical(self, "Update Error", f"Failed to update credential: {e}")

    def delete_credential(self):
        idx = self.list_widget.currentRow()
        if idx < 0 or idx >= len(self._loaded_items):
            QMessageBox.warning(self, "Select Entry", "Select an entry to delete.")
            return
        entry = self._loaded_items[idx]
        confirm = QMessageBox.question(self, "Confirm Delete",
                                       f"Delete credential for '{entry['service_name']}'?",
                                       QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if confirm != QMessageBox.Yes:
            return
        if self.db.delete_credential(entry["id"]):
            QMessageBox.information(self, "Deleted", "Credential deleted successfully.")
            self.load_credentials()
        else:
            QMessageBox.critical(self, "Delete Error", "Failed to delete credential.")

    def lock_vault(self):
        """Lock the vault and prompt user to re-unlock."""
        self.encryption_key = None
        QMessageBox.information(self, "Locked", "Vault locked due to inactivity or manual lock.")
        # Prompt unlock
        if not self.unlock_vault():
            QMessageBox.information(self, "Exit", "Failed to unlock vault. Application will exit.")
            sys.exit(0)
        # Reload after unlocking
        self.load_credentials()


def main():
    app = QApplication(sys.argv)
    window = PasswordVaultApp()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()


