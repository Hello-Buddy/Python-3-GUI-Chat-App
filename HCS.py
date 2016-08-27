#!/usr/bin/env python
import os
import sys
import string
import socket
import logging
import argparse
import platform
from _thread import start_new_thread

class Server:

    
    def __init__(self, host, port):
        
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.text_check = string.ascii_letters + string.digits + string.punctuation + " "
        self.conn_dict = {}
        try:
            self.server.bind((host, port))
        except socket.error as e:
            logging.info("\033[91m {}".format(" ".join(str(e).split(" ")[2:])))
            sys.exit()
        print("#~# Welcome to Haiku Chat #~#")
        print("#~#  Created by Sam Rees  #~#")
        print("#~# Currently Version 1.0 #~#\n\n")
        logging.info("Server is running on port {:d}".format(port))
        self.server.listen(25)

    
    def username(self, conn, addr):
        """Lets the user choose a username"""

        while True:
            try:
                username = conn.recv(4096).strip()
            except ConnectionResetError:
                self.stop_thread(conn, addr)
            try:
                username = str(username, "utf-8").lower()
                for x in username:
                    if x not in self.text_check:
                        raise UnicodeError
            except UnicodeError:
                logging.info("\033[91m{}:{} tried setting their username to unicode\033[0m".format(addr[0], addr[1]))
                try:
                    conn.send(str.encode("Server: Please don't send unicode. Enter a normal username\n"))
                except BrokenPipeError:
                    self.stop_thread(addr, conn)
            else:
                if username not in self.conn_dict.values() and username != "" and username != "server":
                    logging.info("{} set their username as {}".format(addr[0], username))
                    conn.send(str.encode("Your username is now {}\n".format(username)))
                    self.conn_dict[conn] = username.lower()
                    welcome_message = "Server: Please welcome {} to the chat room".format(username)
                    for person in self.conn_dict.keys():
                        if person != conn:
                            try:
                                person.send(str.encode(welcome_message))
                            except BrokenPipeError:
                                pass
                    self.receive(conn, username, addr)
                if username == "":
                    try:
                        conn.send(str.encode("Please enter something for your username\n"))
                    except BrokenPipeError:
                        self.stop_thread(addr, conn)
                else:
                    try:
                        conn.send(str.encode("That username is taken\n"))
                    except BrokenPipeError:
                        self.stop_thread(addr, conn)


    def receive(self, conn, username, addr):
        """Receives and sends messages from connected clients"""

        try:
            while True:
                message = conn.recv(4096).strip()
                try:
                    message = str(message, "utf-8")
                    for x in message:
                        if x not in self.text_check:
                            raise UnicodeError
                except UnicodeError:
                    logging.info("\033[91m{} tried sending unicode\033[0m".format(username))
                    try:
                        conn.send(str.encode("Server: Please don't send unicode. Only send normal messages\n"))
                    except BrokenPipeError:
                        self.stop_thread(addr, conn)
                else:
                    if message != "client_break":
                        logging.info("{} said: {}".format(username, message))
                        self.broadcast(username + ": " + message, conn)
                    elif message == "client_break":
                        self.stop_thread(addr, conn)
        except (BrokenPipeError, ConnectionResetError):
            self.stop_thread(addr, conn)

    
    def broadcast(self, message, conn):
        """Sends a message to all clients connected"""
        
        for person in self.conn_dict.keys():
            if person != conn:
                try:
                    person.send(str.encode(message))
                except (BrokenPipeError, ConnectionResetError):
                    pass


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
            self.broadcast(quit_message, conn)
        except UnboundLocalError:
            pass
        logging.info("\033[91mThread stopped\033[0m")
        while True:
            pass

    
    def run(self):
        """Checks for incoming conenctions"""
        
        logging.info("Wating for connections")
        while True:
            conn, addr = self.server.accept()
            logging.info("Connection from {}:{}".format(addr[0], addr[1]))
            start_new_thread(self.username, (conn, addr))


def main():

    global my_server

    os_sys = platform.system().lower()
    if os_sys == "windows":
        os.system("cls")
    else:
        os.system("clear")

    parser = argparse.ArgumentParser()
    parser.add_argument("port")
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

    my_server = Server(host, port)
    my_server.run()


try:
    if __name__ == "__main__":
        main()
except KeyboardInterrupt:
    my_server.broadcast("server_break", "EXIT")
    logging.info("\033[91mKeypress interuption\033[0m")
    logging.info("\033[91mServer stopped\033[0m")
    sys.exit()