#!/usr/bin/env python
import os
import sys
import socket
import string
import platform
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from PyQt4 import QtGui, QtCore
from _thread import start_new_thread

class MainSend(QtGui.QMainWindow):

	def __init__(self, client, encryption_method = False):

		super(MainSend, self).__init__()
		self.setGeometry(100, 100, 800, 600)
		self.setWindowTitle("Haiku Chat Client V1.1")
		self.setStyleSheet("background-color: #6d6968")
		start_new_thread(self.recv_from_server, ())
		self.client = client
		self.encryption_method = encryption_method

		self.send_button()

	
	def send_button(self):

		self.send_btn = QtGui.QPushButton("Send", self)
		self.send_btn.clicked.connect(self.send_message)
		self.send_btn.resize(100, 45)
		self.send_btn.move(10, 490)
		self.send_btn.setStyleSheet("color: #00ffbc; font-weight: 700")
		self.send_btn.setFocusPolicy(QtCore.Qt.NoFocus)

		self.close_button()


	def close_button(self):

		self.close_btn = QtGui.QPushButton("Disconnect", self)
		self.close_btn.clicked.connect(self.are_you_sure)
		self.close_btn.resize(100, 45)
		self.close_btn.move(10, 545)
		self.close_btn.setStyleSheet("font-weight: 700; color: #00ffbc")
		self.close_btn.setFocusPolicy(QtCore.Qt.NoFocus)

		self.recv_message_field()


	def recv_message_field(self):

		self.recv_message_field_obj = QtGui.QTextEdit(self)
		self.recv_message_field_obj.setStyleSheet("background-color: #9b9897; color: #fff; border-color: #00ffbc")
		self.recv_message_field_obj.move(10, 10)
		self.recv_message_field_obj.resize(780, 470)
		self.recv_message_field_obj.setReadOnly(True)

		self.send_message_field()


	def send_message_field(self):

		self.send_message_field_obj = QtGui.QTextEdit(self)
		self.send_message_field_obj.setStyleSheet("background-color: #9b9897; color: #fff; border-color: #00ffbc")
		self.send_message_field_obj.move(120, 490)
		self.send_message_field_obj.resize(670, 100)

		self.show()


	def send_message(self):
		"""Sends a message to the server"""

		text_to_send = self.send_message_field_obj.toPlainText()
		if len(text_to_send) > 1500:
			self.send_message_field_obj.setText("")
			self.recv_message_field_obj.append("<span style=\"color: #ff0000; font-weight: 700\">Server: </span>Text entered is to long")
		else:
			text_to_send = text_to_send.replace("\n", "")
			if text_to_send:
				if text_to_send != "client_break" and text_to_send != "server_break":
					if text_to_send[0] != "/":
						self.recv_message_field_obj.append("<span style=\"color: #00ffbc; font-weight: 700\">You: </span>" + text_to_send)
					if self.encryption_method:
						text_to_send = self.encryption_method.encrypt(text_to_send)
					client_send_ret = self.client.send_message(text_to_send)
					self.send_message_field_obj.setText("")
					if client_send_ret == "broken":
						self.recv_message_field_obj.append("<span style=\"color: #ff0000; font-weight: 700\">" + \
							"Server is no longer running.\n" + \
							"Press the quit button to exit.</span>")
					if text_to_send[0] == "/":
						command_return = self.client.recv_messages()
						if self.encryption_method:
							self.encryption_method.decrypt(command_return)
				else:
					self.send_message_field_obj.setText("")
		os.system(clear)


	def recv_from_server(self):
		"""Receives and posts messages from the server"""

		if self.encryption_method:
			self.client.send_message(self.encryption_method.encrypt("ready"))
		else:
			self.client.send_message("ready")
		while True:
			to_append = self.client.recv_messages()
			if to_append:
				if self.encryption_method:
					to_append = self.encryption_method.decrypt(to_append)
				try:
					if "unicode" in to_append:
						self.recv_message_field_obj.append("Server: Please don't enter unicode")
					elif to_append == "break" or to_append == "server_break":
						self.recv_message_field_obj.append("<span style=\"color: #ff0000; font-weight: 700\">" + \
							"Server is no longer running.\n" + \
							"Press the quit button to exit.</span>")
					else:
						self.recv_message_field_obj.append(to_append)
				except (AttributeError, TypeError):
					self._is_running = False


	def are_you_sure(self):
		"""Makes sure the user wants to exit aafter clicking the disconnect button"""

		self.send_btn.setText("Yes")
		self.close_btn.setText("No")
		self.send_btn.clicked.connect(self.disconnect)
		self.close_btn.clicked.connect(self.ret_to_normal)


	def ret_to_normal(self):
		"""Returns the buttons back to normal values"""

		self.send_btn.setText("Send")
		self.close_btn.setText("Disconnect")
		self.send_btn.clicked.connect(self.send_message)
		self.close_btn.clicked.connect(self.are_you_sure)


	def disconnect(self):
		"""Tells the serevr you are leaving"""

		client.send_message("client_break")
		self.close()


class ChooseServer(QtGui.QMainWindow):

	def __init__(self):
		"""Creates the main window for the login"""

		super(ChooseServer, self).__init__()
		self.setGeometry(100, 100, 500, 200)
		self.setWindowTitle("Haiku Chat Join Server")
		self.setStyleSheet("background-color: #6d6968")
		
		self.input_field()


	def input_field(self):
		"""Creates input fields for the IP and port of the server"""

		self.host_field = QtGui.QLineEdit(self)
		self.host_field.resize(250, 25)
		self.host_field.move(125, 50)
		self.host_field.setStyleSheet("border: 3px solid #00ffbc; color: #fff; background-color: #9b9897")

		self.port_field = QtGui.QLineEdit(self)
		self.port_field.setMaxLength(5)
		self.port_field.resize(250, 25)
		self.port_field.move(125, 100)
		self.port_field.setStyleSheet("border: 3px solid #00ffbc; color: #fff; background-color: #9b9897")

		self.error_message = QtGui.QLabel("", self)
		self.error_message.move(50, 10)
		self.error_message.resize(500, 25)
		host_label = QtGui.QLabel("Host", self)
		host_label.move(50, 47)
		host_label.setStyleSheet("background: transparent; font-weight: 700; color: #00ffbc")
		port_label = QtGui.QLabel("Port", self)
		port_label.move(50, 97)
		port_label.setStyleSheet("background: transparent; font-weight: 700; color: #00ffbc")

		self.submit_button()


	def submit_button(self):
		"""Adds submit button"""

		submit_btn = QtGui.QPushButton("Submit", self)
		submit_btn.clicked.connect(self.check_input)
		submit_btn.resize(100, 25)
		submit_btn.move(200, 150)
		submit_btn.setStyleSheet("color: #00ffbc; font-weight: 700")
		submit_btn.setFocusPolicy(QtCore.Qt.NoFocus)
		self.host_field.returnPressed.connect(submit_btn.click)
		self.port_field.returnPressed.connect(submit_btn.click)


	def check_input(self):
		"""Checks if the user entered a valid input"""

		global client

		self.host_field_text = self.host_field.text()
		self.port_field_text = self.port_field.text()

		try:
			if self.host_field_text and self.port_field_text:
				if "." in self.port_field_text:
					self.display_error("Port field can't contain decimals")
					raise AttributeError
				else:
					if int(self.port_field_text) in range(500, 65000):
						self.port_field_text = int(self.port_field_text)
						int(self.host_field_text.replace(".", ""))
					else:
						self.display_error("Port must be in range of 500-65,000")
						raise AttributeError
			else:
				raise NameError
		except NameError:
			self.display_error("Both fields must have an input")
		except ValueError:
			self.display_error("Both fields can only have decimals and numbers")
		except AttributeError:
			pass
		else:
			client = Client(self.host_field_text, self.port_field_text)
			if client.connect() == "good":
				self.close()
			else:
				self.display_error("Can't connect to host and port supplied")


	def display_error(self, error_message):
		"""Shows an error message on the login screen"""

		self.error_message.setText(error_message)
		self.error_message.setStyleSheet("color: red; font-weight: 700")


class GetUsername(QtGui.QMainWindow):
	
	def __init__(self, client, encryption_method = False):

		super(GetUsername, self).__init__()
		self.setGeometry(100, 100, 500, 200)
		self.setWindowTitle("Haiku Chat Client V1.1")
		self.setStyleSheet("background-color: #6d6968")
		self.client = client
		self.encryption_method = encryption_method
		self.username_field()


	def username_field(self):
		"""Creates a username and label for user to input their username"""

		self.username_field_obj = QtGui.QLineEdit(self)
		self.username_field_obj.move(125, 50)
		self.username_field_obj.resize(250, 25)
		self.username_field_obj.setMaxLength(32)
		self.username_field_obj.setStyleSheet("border: 3px solid #00ffbc; color: #fff; background-color: #9b9897")
		username_label = QtGui.QLabel("Username", self)
		username_label.move(50, 47)
		username_label.setStyleSheet("background: transparent; font-weight: 700; color: #00ffbc")
		self.username_error = QtGui.QLabel("", self)
		self.username_error.setStyleSheet("color: red; font-weight: 700; background: transparent")
		self.username_error.move(50, 10)
		self.username_error.resize(500, 25)
		self.username_button()


	def check_input(self, message):
		"""Checks a persons input in the username field"""

		try:
			if "Your username is now" in message:
				return "DONE"
			elif "unicode" in message:
				self.display_error("Please don't enter unicode")
			elif "That username is taken" in message:
				self.display_error("Username is taken")
			else:
				self.display_error("Username not avalible")
			self.username_field_obj.setText("")
		except TypeError:
			self.display_error("Server no longer online")


	def display_error(self, message):
		"""Displays an error if one occurs"""

		self.username_error.setText(message)


	def username_button(self):
		"""Submit button for the username window"""

		self.username_submit_button = QtGui.QPushButton("Submit", self)
		self.username_submit_button.move(200, 100)
		self.username_submit_button.resize(100, 25)
		self.username_submit_button.setStyleSheet("color: #00ffbc; font-weight: 700")
		self.username_submit_button.clicked.connect(self.username)
		self.username_submit_button.setFocusPolicy(QtCore.Qt.NoFocus)
		self.username_field_obj.returnPressed.connect(self.username_submit_button.click)


	def username(self):
		"""Gets and sends a username to the server"""

		user = self.username_field_obj.text().strip()
		user = user.replace(" ", "_")
		if user:
			if self.encryption_method:
				user = self.encryption_method.encrypt(user)
			ret_test = self.client.send_message(user)
			if ret_test == "break":
				self.display_error("Server is no longer connected.")
			else:
				ret_message = self.client.recv_messages()
				if self.encryption_method:
					ret_message = self.encryption_method.decrypt(ret_message)
				if ret_message == "break":
					self.display_error("Server is no longer connected.")
				else:
					self.user_check = self.check_input(ret_message)
					if self.user_check == "DONE":
						self.close()
		else:
			self.display_error("You must enter a username")


class EncryptKey(QtGui.QMainWindow):

	def __init__(self, client):

		super(EncryptKey, self).__init__()
		self.setGeometry(100, 100, 500, 200)
		self.setWindowTitle("Haiku Chat Encryption Key")
		self.setStyleSheet("background-color: #6d6968")
		self.client = client
		self.IV = b"Ha1KU-CHat_15c0L"

		self.key_button()


	def key_button(self):
		"""Button to submit key"""

		self.button = QtGui.QPushButton("Submit", self)
		self.button.resize(100, 25)
		self.button.move(200, 100)
		self.button.setFocusPolicy(QtCore.Qt.NoFocus)
		self.button.clicked.connect(self.check_key)
		self.button.setStyleSheet("color: #00ffbc; font-weight: 700")

		self.key_field()


	def key_field(self):
		"""Text field for the user to enter the server's encryption key"""

		self.key = QtGui.QLineEdit(self)
		self.key.setEchoMode(QtGui.QLineEdit.Password)
		self.key.resize(250, 25)
		self.key.move(125, 50)
		self.key.setStyleSheet("color: #fff; border: 3px solid #00ffbc; background-color: #9b9897")
		self.key.returnPressed.connect(self.button.click)

		self.key_label = QtGui.QLabel("Key", self)
		self.key_label.move(75, 47)
		self.key_label.setStyleSheet("background: transparent; color: #00ffbc; font-weight: 700")

		self.display_warning("")


	def display_warning(self, message):
		"""Displays a warning if something goes wrong"""

		self.warning = QtGui.QLabel(message, self)
		self.warning.resize(500, 25)
		self.warning.move(50, 10)
		self.warning.setStyleSheet("color: red; font-weight: 700; background: transparent")


	def check_key(self):
		"""Checks if the key is correct"""

		self.client.send_message("READY")
		key = self.key.text()
		test_text = self.client.recv_messages()
		decrypted_test = self.decrypt(test_text, key)
		check_server = self.encrypt("test_MESSAGE", key)
		ret_test = self.client.send_message(check_server)
		if ret_test == "break":
			self.warning.setText("Server is no longer online")
		else:
			self.ret_check_server = self.client.recv_messages()
			self.ret_check_server = self.decrypt(self.ret_check_server, key)
			if self.ret_check_server:
				self.encryption_key = key
				self.close()
			else:
				self.client.recv_messages()
				self.warning.setText("Key is incorrect")
				self.key.setText("")


	def encrypt(self, message, key):
		"""Encrypts a message"""

		password = SHA256.new(key.encode("utf-8")).digest()
		encryptor = AES.new(password, AES.MODE_CBC, self.IV)
		message = bytes(message, "utf-8")
		if len(message) % 16 != 0:
			message += b" " * (16 - (len(message) % 16))
		message = encryptor.encrypt(message)
		return message


	def decrypt(self, message, key):
		"""Decrypts a message"""

		password = SHA256.new(key.encode("utf-8")).digest()
		try:
			decryptor = AES.new(password, AES.MODE_CBC, self.IV)
			if message != "crypt_FALSE":
				if len(message) % 16 != 0:
					message += b" " * (16 - (len(message) % 16))
				message = decryptor.decrypt(message)
				message = str(message, "utf-8").strip()
				return True if message == "test_MESSAGE" or message == "crypt_TRUE" else False
		except UnicodeError:
			return False


class Client:

	def __init__(self, host, port):

		self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.host = host
		self.port = port


	def connect(self):
		"""Tests to see if the user's input can be connected to"""

		try:
			self.server.connect((self.host, self.port))
			return "good"
		except socket.error as e:
			return "bad"


	def recv_messages(self, key = False):
		"""Receives and appends messages from the server"""

		try:
			data = self.server.recv(4096).strip()
			try:
				data = str(data, "utf-8")
			except UnicodeError:
				pass
		except ConnectionResetError:
			return "break"
		else:
			if data:
				return data


	def send_message(self, message):
		"""Sends a message to the server"""

		if message:
			try:
				try:
					str(message, "utf-8")
				except UnicodeError:
					self.server.send(message)
				except TypeError:
					self.server.send(str.encode(message))
				else:
					self.server.send(str.encode(message))
			except BrokenPipeError:
				return "break"
			else:
				return "sent"


class EncryptionMethod:

	def __init__(self, password, IV):

		self.IV = IV
		self.password = SHA256.new(password.encode("utf-8")).digest()

	def encrypt(self, message):
		"""Encrypts a message given to it"""
		
		if message:
			message = bytes(message, "utf-8")
			encryptor = AES.new(self.password, AES.MODE_CBC, self.IV)
			if len(message) % 16 != 0:
				message += b" " * (16 - (len(message) % 16))
			message = encryptor.encrypt(message)
			return message


	def decrypt(self, message):
		"""Decrypts a message given to it"""

		decryptor = AES.new(self.password, AES.MODE_CBC, self.IV)
		try:
			message = decryptor.decrypt(message)
			return str(message, "utf-8").strip()
		except (UnicodeError, TypeError, ValueError):
			return False


def main():

	global clear

	if platform.system().lower() == "windows":
		clear = "cls"
	else:
		clear = "clear"

	os.system(clear)

	app = QtGui.QApplication(sys.argv)

	login_screen = ChooseServer()
	login_screen.show()
	app.exec_()

	try:
		encrypt = client.recv_messages()

		if encrypt == "encrypt_TRUE":
			encrypt_test = EncryptKey(client)
			encrypt_test.show()
			app.exec_()
			if encrypt_test.ret_check_server:
				encryption_method = EncryptionMethod(encrypt_test.encryption_key, encrypt_test.IV)

		if encrypt == "encrypt_TRUE":
			username = GetUsername(client, encryption_method)
		else:
			username = GetUsername(client)
		username.show()
		app.exec_()
		username.close()

		if username.user_check == "DONE":
			if encrypt == "encrypt_TRUE":
				main_window = MainSend(client, encryption_method)
			else:
				main_window = MainSend(client)
			main_window.show()
			app.exec_()
	except (AttributeError, NameError):
		sys.exit()

	try:
		if encryption_method:
			break_text = encryption_method.encrypt("client_break")
	except (UnboundLocalError, NameError):
		break_text = "client_break"
	client.send_message(break_text)
	sys.exit()

try:
	if __name__ == "__main__":
		main()
except KeyboardInterrupt:
	try:
		if encryption_method:
			break_text = encryption_method.encrypt("client_break")
	except (UnboundLocalError, NameError):
		break_text = "client_break"
	client.send_message(break_text)
	sys.exit()