import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QTextEdit,
    QPushButton, QVBoxLayout, QMessageBox, QLineEdit
)
from cryptography.fernet import Fernet

class CryptoApp(QWidget):
    def __init__(self):
        super().__init__()
        self.key = None
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("AES Encryption & Decryption Tool Made By Ayush")
        self.setGeometry(200, 200, 600, 500)

        layout = QVBoxLayout()

        self.key_label = QLabel("Secret Key:")
        self.key_input = QLineEdit()
        layout.addWidget(self.key_label)
        layout.addWidget(self.key_input)

        self.gen_key_btn = QPushButton("Generate Key")
        self.gen_key_btn.clicked.connect(self.generate_key)
        layout.addWidget(self.gen_key_btn)

        self.input_label = QLabel("Message or Text -> Encrypt/ Encrypted Text -> Decrypt:")
        self.input_text = QTextEdit()
        layout.addWidget(self.input_label)
        layout.addWidget(self.input_text)

        self.encrypt_btn = QPushButton("Encrypt")
        self.encrypt_btn.clicked.connect(self.encrypt_message)
        layout.addWidget(self.encrypt_btn)

        self.decrypt_btn = QPushButton("Decrypt")
        self.decrypt_btn.clicked.connect(self.decrypt_message)
        layout.addWidget(self.decrypt_btn)

        self.output_label = QLabel("Output:")
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        layout.addWidget(self.output_label)
        layout.addWidget(self.output_text)

        self.setLayout(layout)

    def generate_key(self):
        self.key = Fernet.generate_key()
        self.key_input.setText(self.key.decode())
        QMessageBox.information(self, "Key Generated", "Secret key generated.\nSave it securely.")

    def encrypt_message(self):
        if not self.key:
            QMessageBox.warning(self, "Error", "Generate a key first.")
            return
        message = self.input_text.toPlainText().strip()
        if not message:
            QMessageBox.warning(self, "Error", "Enter a message to encrypt.")
            return
        fernet = Fernet(self.key)
        encrypted = fernet.encrypt(message.encode())
        self.output_text.setText(encrypted.decode())

    def decrypt_message(self):
        if not self.key:
            QMessageBox.warning(self, "Error", "Generate a key first.")
            return
        encrypted_text = self.input_text.toPlainText().strip()
        try:
            fernet = Fernet(self.key)
            decrypted = fernet.decrypt(encrypted_text.encode())
            self.output_text.setText(decrypted.decode())
        except:
            QMessageBox.critical(self, "Error", "Invalid encrypted text or key.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = CryptoApp()
    window.show()
    sys.exit(app.exec_())
