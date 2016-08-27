#!/usr/bin/env python
import os
import sys
import signal
import socket
import string
import platform
from PyQt4 import QtGui, QtCore
from _thread import start_new_thread

class MainSend(QtGui.QMainWindow):

    def __init__(self, client):

        super(MainSend, self).__init__()
        self.setGeometry(100, 100, 800, 600)
        self.setWindowTitle("Haiku Chat Client V1.0")
        self.setStyleSheet("background-color: #6d6968")
        start_new_thread(self.recv_from_server, ())
        self.client = client

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
        self.recv_message_field_obj.setStyleSheet("background-color: #9b9897; color: #fff;")
        self.recv_message_field_obj.move(10, 10)
        self.recv_message_field_obj.resize(780, 470)
        self.recv_message_field_obj.setReadOnly(True)

        self.send_message_field()


    def send_message_field(self):

        self.send_message_field_obj = QtGui.QTextEdit(self)
        self.send_message_field_obj.setStyleSheet("background-color: #9b9897; color: #fff;")
        self.send_message_field_obj.move(120, 490)
        self.send_message_field_obj.resize(670, 100)

        self.show()


    def send_message(self):
        """Sends a message to the server"""

        text_to_send = self.send_message_field_obj.toPlainText()
        if text_to_send:
            if text_to_send != "client_break" and text_to_send != "server_break":
                self.recv_message_field_obj.append("You: " + text_to_send)
                client_send_ret = self.client.send_message(text_to_send)
                self.send_message_field_obj.repaint()
                self.send_message_field_obj.setText("")
                if client_send_ret == "broken":
                    self.recv_message_field_obj.append("Server is no longer connected.\n" + \
                        "Please click the quit button to disconnect")
            else:
                self.send_message_field_obj.repaint()
                self.send_message_field_obj.setText("")
        os.system(clear)


    def recv_from_server(self):
        """Receives and posts messages from the server"""

        while True:
            to_append = self.client.recv_messages()
            try:
                if "unicode" in to_append:
                    self.recv_message_field_obj.append("Server: Please don't enter unicode")
                elif to_append == "break" or to_append == "server_break":
                    self.recv_message_field_obj.append("Server is no longer running.\n" + \
                        "Press the quit button to exit.")
                else:
                    self.recv_message_field_obj.append(to_append.strip())
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
        submit_btn.clicked.connect(self.check_input)#Make it so this click joins the server
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

        self.error_message.repaint()
        self.error_message.setText(error_message)
        self.error_message.setStyleSheet("color: red; font-weight: 700")


class GetUsername(QtGui.QMainWindow):
    
    def __init__(self, host, port, client):

        super(GetUsername, self).__init__()
        self.setGeometry(100, 100, 500, 200)
        self.setWindowTitle("Haiku Chat Client V1.0")
        self.setStyleSheet("background-color: #6d6968")
        self.client = client        
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

        if "Your username is now" in message:
            self.close()
        elif "unicode" in message:
            self.display_error("Please don't enter unicode")
        else:
            self.display_error("Username is taken")


    def display_error(self, message):
        """Displays an error if one occurs"""

        self.username_error.repaint()
        self.username_error.setText(message)


    def display_disconnect_button(self):
        """Shows a disconnect button if the server goes offline"""

        quit_button = QtGui.QPushButton("Quit", self)
        quit_button.move(200, 150)
        quit_button.setFocusPolicy(QtCore.Qt.NoFocus)
        quit_button.setStyleSheet("font-weight: 700; color: #00ffbc")
        quit_button.resize(100, 25)
        quit_button.clicked.connect(self.close())
        self.username_submit_button.move(200, 150)


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
        user = "_".join(user.split(" "))
        try:
            self.client.server.send(str.encode(user))
        except BrokenPipeError:
            self.display_error("Server is no longer connected.")
        else:
            try:
                ret_message = self.client.server.recv(4096).strip()
                ret_message = str(ret_message, "utf-8")
            except ConnectionResetError:
                self.display_error("Server is no longer connected.")
            else:
                user_check = self.check_input(ret_message)
                if user_check:
                    pass


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


    def recv_messages(self):
        """Receives and appends messages from the server"""

        try:
            data = self.server.recv(4096).strip()
            data = str(data, "utf-8")
        except ConnectionResetError:
            return "break"
        else:
            if data:
                return data


    def send_message(self, message):
        """Sends a message to the server"""

        try:
            self.server.send(str.encode(message))
        except BrokenPipeError:
            return "break"
        else:
            return "sent"


def main():

    global clear

    print("\x1b[8;1;1t")

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
        username = GetUsername(login_screen.host_field_text, login_screen.port_field_text, client)
        username.show()
        app.exec_()
        main_window = MainSend(client)
        main_window.show()
        app.exec_()
    except AttributeError:
        os.kill(os.getppid(), signal.SIGHUP)

    os.kill(os.getppid(), signal.SIGHUP)

try:
    if __name__ == "__main__":
        main()
except KeyboardInterrupt:
    client.send_message("client_break")
    os.kill(os.getppid(), signal.SIGHUP)