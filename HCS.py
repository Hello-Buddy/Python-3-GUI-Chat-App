#!/usr/bin/env python
import os
import sys
import string
import socket
import logging
import argparse
import platform
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from _thread import start_new_thread

class Server:

	
	def __init__(self, host, port, encryption = False):
		
		self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.text_check = string.ascii_letters + string.digits + string.punctuation + " "
		self.conn_dict = {}
		try:
			self.server.bind((host, port))
		except socket.error as e:
			logging.info("\033[91m {}".format(" ".join(str(e).split(" ")[2:])))
			sys.exit()

		self.encryption_method = encryption
		print("#~# Welcome to Haiku Chat #~#")
		print("#~#  Created by Sam Rees  #~#")
		print("#~# Currently Version 1.0 #~#\n\n")
		if self.encryption_method:
			logging.info("Encryption: True")
		else:
			logging.info("Encryption: False")
		logging.info("Server is running on port {:d}".format(port))
		self.server.listen(25)

	
	def username(self, conn, addr):
		"""Lets the user choose a username"""

		counter = 1
		while True:
			if counter == 1:
				if self.encryption_method:
					self.send_message("encrypt_TRUE", conn)
					while True:
						encrypt_test = self.test_encryption(conn, addr)
						if encrypt_test:
							counter = 2
							break
						else:
							self.send_message("wrong", conn)
				else:
					self.send_message("encrypt_FALSE", conn)
					counter = 2
			username = self.recv_message(conn, addr)
			if username == "client_break":
				self.stop_thread(addr, conn)
			if username == "break":
				self.stop_thread(conn, addr)
			try:
				for x in username.lower():
					if x not in self.text_check:
						raise UnicodeError
			except UnicodeError:
				logging.info("\033[91m{}:{} tried setting their username to unicode\033[0m".format(addr[0], addr[1]))
				send_test = self.send_message("Server: Please don't send unicode. Enter a normal username\n", conn)
				if send_test == "break":
					self.stop_thread(addr, conn)
			else:
				if username not in self.conn_dict.values() and username != "" and username != "server":
					logging.info("{} set their username as {}".format(addr[0], username))
					self.send_message("Your username is now {}".format(username), conn)
					self.conn_dict[conn] = username.lower()
					welcome_message = "Server: Please welcome {} to the chat room".format(username)
					self.broadcast(welcome_message, conn, addr)
					self.receive(conn, username, addr)
				if username == "":
					send_test = self.send_message("Please enter something for your username\n", conn)
					if send_test == "break":
						self.stop_thread(addr, conn)
				else:
					send_test = self.send_message("That username is taken\n", conn)
					if self.send_message == "break":
						self.stop_thread(addr, conn)


	def receive(self, conn, username, addr):
		"""Receives and sends messages from connected clients"""

		while True:
			message = self.recv_message(conn, addr)
			try:
				for x in message:
					if x not in self.text_check:
						raise UnicodeError
			except UnicodeError:
				logging.info("\033[91m{} tried sending unicode\033[0m".format(username))
				sending_test = self.send_message("Server: Please don't send unicode. Only send normal messages\n", conn)
				if sending_test == "break":
					self.stop_thread(addr, conn)
			else:
				if message != "client_break" and message != "" and message != "break":
					logging.info("{} said: {}".format(username, message))
					self.broadcast(username + ": " + message, conn, addr)
				elif message == "client_break":
					self.stop_thread(addr, conn)

	
	def broadcast(self, message, conn, addr):
		"""Sends a message to all clients connected"""
		
		for person in self.conn_dict.keys():
			if message != "client_break":
				if person != conn:
					try:
						if self.encryption_method:
							person.send(self.encryption_method.encrypt(message))
						else:
							person.send(str.encode(message))
					except (BrokenPipeError, ConnectionResetError):
						pass
			else:
				self.stop_thread(addr, conn)


	def send_message(self, message, conn):
		"""Sends a message"""

		try:
			if self.encryption_method and message != "encrypt_TRUE" and message != "crypt_FALSE":
				message = self.encryption_method.encrypt(message)
				try:
					conn.send(message)
				except ConnectionResetError:
					self.stop_thread(addr, conn)
			else:
				conn.send(str.encode(message))
		except BrokenPipeError:
			return "break"
		else:
			return "sent"


	def recv_message(self, conn, addr):
		"""Receives a message from the server"""

		try:
			message = conn.recv(4096)
			try:
				message = str(message, "utf-8")
			except (UnicodeError, UnicodeDecodeError):
				message = self.encryption_method.decrypt(message)
			if message == "client_break":
				return "break"
		except ConnectionResetError:
			return self.stop_thread(addr, conn)
		else:
			if message:
				return message
			else:
				return "client_break"


	def stop_thread(self, addr, conn):
		"""Stops a user's thread if they disconnect"""

		try:
			error = ("\033[91m{}:{} / {} has left the room\033[0m".format(addr[0], addr[1], self.conn_dict[conn]))
			quit_message = "Server: {} has left the room".format(self.conn_dict[conn])
		except (KeyError, TypeError):
			try:
				error = ("\033[91m{}:{} has left the room\033[0m".format(addr[0], addr[1]))
			except TypeError:
				error = ("\033[91mA user has disconnected\033[0m")
		self._is_running = False
		self.conn_dict[conn] = ""
		logging.info("\033[91m{}\033[0m".format(error))
		try:
			self.broadcast(quit_message, conn, addr)
		except UnboundLocalError:
			pass
		logging.info("\033[91mThread stopped\033[0m")
		while True:
			pass

	
	def run(self):
		"""Checks for incoming conenctions"""
		
		logging.info("Wating for connections\n")
		while True:
			conn, addr = self.server.accept()
			logging.info("Connection from {}:{}".format(addr[0], addr[1]))
			start_new_thread(self.username, (conn, addr))


	def test_encryption(self, conn, addr):
		"""Tests the user's key input"""

		try:
			self.recv_message(conn, addr)
			conn.send(self.encryption_method.encrypt("test_MESSAGE"))
		except BrokenPipeError:
			self.stop_thread(addr, conn)
		else:
			try:
				check = conn.recv(4096).strip()
			except ConnectionResetError:
				self.stop_thread(addr, conn)
			else:
				check = self.encryption_method.decrypt(check)
				if check == "test_MESSAGE":
					self.send_message("crypt_TRUE", conn)
					return True
				else:
					self.send_message("crypt_FALSE", conn)
					return False


class Encrypt:

	def __init__(self, key):

		self.IV = b"Ha1KU-CHat_15c0L"
		self.key = SHA256.new(key.encode("utf-8")).digest()


	def encrypt(self, message):
		"""Encrypts a message"""

		message = bytes(message, "utf-8")
		if len(message) % 16 != 0:
			message += b" " * (16 - (len(message) % 16))
		encryptor = AES.new(self.key, AES.MODE_CBC, self.IV)
		return encryptor.encrypt(message)


	def decrypt(self, message):
		"""Decrypts a message"""

		try:
			if len(message) % 16 != 0:
				message += b" " * (16 - (len(message) % 16))
			decryptor = AES.new(self.key, AES.MODE_CBC, self.IV)
			try:
				return str(decryptor.decrypt(message), "utf-8").strip()
			except UnicodeDecodeError:
				return False
		except ValueError:
			pass


def main():

	global my_server

	os_sys = platform.system().lower()
	if os_sys == "windows":
		os.system("cls")
	else:
		os.system("clear")

	parser = argparse.ArgumentParser()
	parser.add_argument("port", help = "Port for the server to run on")
	parser.add_argument("--key", "-k", help = "Key for people to join")
	args = parser.parse_args()

	logging.basicConfig(level = logging.INFO,
						format = "[%(asctime)s]: %(message)s",
						datefmt = "%d/%m/%y %H:%M:%S")

	try:
		if int(args.port) in range(500, 60000):
			host = ""
			port = int(args.port)
		else:
			raise ValueError
	except ValueError:
		logging.info("Port number must be a number and be between 500 and 60,000")
		sys.exit()

	if args.key:
		encryption = Encrypt(args.key)
		my_server = Server(host, port, encryption)
	else:
		my_server = Server(host, port)
	my_server.run()


try:
	if __name__ == "__main__":
		main()
except KeyboardInterrupt:
	my_server.broadcast("server_break", "EXIT", "SPEC")
	logging.info("\033[91mKeypress interuption\033[0m")
	logging.info("\033[91mServer stopped\033[0m")
	sys.exit()