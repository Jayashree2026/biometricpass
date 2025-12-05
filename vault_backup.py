import json
from PyQt5.QtWidgets import QFileDialog, QMessageBox
from crypto_utils import encrypt_data, decrypt_data

def export_vault(db_manager, master_key, parent=None):
    path, _ = QFileDialog.getSaveFileName(parent, "Export Vault Backup", "", "Encrypted Files (*.enc)")
    if not path:
        return False
    data = {
        "credentials": db_manager.get_credentials(),
        "config": db_manager.get_all_config()
    }
    json_data = json.dumps(data).encode("utf-8")
    ciphertext, iv, tag = encrypt_data(json_data, master_key)
    with open(path, "wb") as f:
        f.write(iv + tag + ciphertext)
    QMessageBox.information(parent, "Export Success", f"Vault exported successfully to {path}")
    return True

def import_vault(db_manager, master_key, parent=None):
    path, _ = QFileDialog.getOpenFileName(parent, "Import Vault Backup", "", "Encrypted Files (*.enc)")
    if not path:
        return False
    with open(path, "rb") as f:
        data = f.read()
    iv, tag, ciphertext = data[:16], data[16:32], data[32:]
    try:
        decrypted = decrypt_data(ciphertext, iv, tag, master_key)
        vault_data = json.loads(decrypted)
        # Restore config
        for k, v in vault_data["config"].items():
            db_manager.save_config(k, v)
        # Restore credentials
        for row in vault_data["credentials"]:
            db_manager.save_credential(*row)
        QMessageBox.information(parent, "Import Success", "Vault imported successfully!")
        return True
    except Exception as e:
        QMessageBox.critical(parent, "Import Error", f"Failed to import vault: {e}")
        return False
