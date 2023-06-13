import sys
import os
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QFileDialog, QMessageBox
from PyQt5.QtGui import QFont
from cryptography.fernet import Fernet


class GpLock(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("GpLock")
        self.setFixedSize(400, 300)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        self.layout = QVBoxLayout()
        self.central_widget.setLayout(self.layout)

        self.password_label = QLabel("Enter Password:")
        self.password_label.setFont(QFont("Arial", 12))
        self.layout.addWidget(self.password_label)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.layout.addWidget(self.password_input)

        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.login)
        self.layout.addWidget(self.login_button)

        self.encrypt_button = QPushButton("Encrypt Directory")
        self.encrypt_button.clicked.connect(self.encrypt_directory)
        self.encrypt_button.setEnabled(False)
        self.layout.addWidget(self.encrypt_button)

        self.decrypt_button = QPushButton("Decrypt Directory")
        self.decrypt_button.clicked.connect(self.decrypt_directory)
        self.decrypt_button.setEnabled(False)
        self.layout.addWidget(self.decrypt_button)

        self.password = None
        self.key = None

    import os

    # ...

    def login(self):
        entered_password = self.password_input.text()

        if self.password is None:
            # First launch, prompt to create a password
            if entered_password:
                self.password = entered_password
                self.password_input.setText("")
                self.password_label.setText("Enter Password:")
                self.login_button.setText("Login")
                self.encrypt_button.setEnabled(True)
                self.decrypt_button.setEnabled(True)
                self.set_password_env()
                self.generate_key()
            else:
                QMessageBox.warning(self, "Error", "Password cannot be empty!")
        else:
            # Subsequent launches, prompt for the password
            if entered_password == self.get_password_env():
                self.password_input.setText("")
                self.password_label.setText("Enter Password:")
                self.login_button.setText("Login")
                self.encrypt_button.setEnabled(True)
                self.decrypt_button.setEnabled(True)
            else:
                QMessageBox.warning(self, "Error", "Incorrect password!")

    def set_password_env(self):
        # Set the password as an environment variable
        os.environ["GPLOCK_PASSWORD"] = self.password

    def get_password_env(self):
        # Get the password from the environment variable
        return os.environ.get("GPLOCK_PASSWORD", "")

    def generate_key(self):
        # Generate a key based on the entered password
        self.key = Fernet.generate_key()

    def encrypt_directory(self):
        directory = QFileDialog.getExistingDirectory(self, "Select Directory to Encrypt")
        if directory:
            # Check if this script file is within the selected directory
            script_path = os.path.abspath(__file__)
            if script_path.startswith(directory):
                QMessageBox.warning(self, "Error", "Cannot encrypt the script file itself!")
                return

            # Implement the directory encryption logic here
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    # Skip encrypting the script file if it resides within the selected directory
                    if file_path == script_path:
                        continue
                    # Encrypt the file
                    self.encrypt_file(file_path)

            QMessageBox.information(self, "Success", "Directory encryption completed.")

    def encrypt_file(self, file_path):
        # Read the file contents
        with open(file_path, "rb") as file:
            data = file.read()

        # Encrypt the data using the generated key
        cipher = Fernet(self.key)
        encrypted_data = cipher.encrypt(data)

        # Write the encrypted data back to the file
        with open(file_path, "wb") as file:
            file.write(encrypted_data)

    def decrypt_directory(self):
        directory = QFileDialog.getExistingDirectory(self, "Select Directory to Decrypt")
        if directory:
            # Implement the directory decryption logic here
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    # Decrypt the file
                    self.decrypt_file(file_path)

            QMessageBox.information(self, "Success", "Directory decryption completed.")

    def decrypt_file(self, file_path):
        # Read the file contents
        with open(file_path, "rb") as file:
            encrypted_data = file.read()

        # Decrypt the data using the generated key
        cipher = Fernet(self.key)
        decrypted_data = cipher.decrypt(encrypted_data)

        # Write the decrypted data back to the file
        with open(file_path, "wb") as file:
            file.write(decrypted_data)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = GpLock()
    window.show()
    sys.exit(app.exec_())
