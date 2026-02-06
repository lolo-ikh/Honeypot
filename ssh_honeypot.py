# for more info on SSH: check this youtube video: https://www.youtube.com/watch?v=P0Fk-K2eZF8
# i have created server.key and sever.key.pub using the command: ssh-keygen -t rsa -b 2048 -f server.key
# Libraries
import logging
from logging.handlers import RotatingFileHandler
import socket
import threading
import paramiko # Paramiko is a Python library that provides an implementation of the SSHv2 protocol, allowing us to create an SSH server and handle SSH connections.
# Constants
logging_format = logging.Formatter('%(message)s')
SSH_BANNER = "SSH-2.0-MySSHServer_1.0" # This is the banner that the SSH server will present to clients when they connect. It identifies the server and its version.
host_key = paramiko.RSAKey(filename='server.key') # We load the RSA host key from the file 'server.key

# Loggers & Logging Files
funnel_logger = logging.getLogger('FunnelLogger')
funnel_logger.setLevel(logging.INFO)
funnel_handler = RotatingFileHandler('audits.log', maxBytes=2000, backupCount=5) # audits.log will store the info f the ip password username.
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

creds_logger = logging.getLogger('CredsLogger')
creds_logger.setLevel(logging.INFO)
creds_handler = RotatingFileHandler('cmd_audits.log', maxBytes=2000, backupCount=5) # cmd_audits.log will store the info of the commands executed by the attacker.
creds_handler.setFormatter(logging_format)
creds_logger.addHandler(creds_handler)


# Emulated Shell
def emulated_shell(channel, client_ip): # dialog is our way to communicate or sending messages over the ssh connection
    channel.send(b'lolo-jumpbox2$ ') # This is the prompt that the attacker will see when they connect to the honeypot. It mimics a typical shell prompt.
    command = b"" # We initialize an empty byte string to store the command that the attacker will type.
    while True: 
        char = channel.recv(1) 
        channel.send(char) # Echo the character back to the attacker, so they see what they are typing.
        if not char:
            channel.close() # If the attacker closes the connection, we close the channel.
        command += char # We append the received character to the command variable.
        if char == b'\r':
            if command.strip() == b'exit': # If the attacker types 'exit', we close the channel.
                response = b'\nGoodbye!\n'
                channel.close()
            elif command.strip() == b'pwd':
                response = b'\n/usr/local/' + b'\r\n' # If the attacker types 'pwd', we respond with a fake directory path.
            elif command.strip() == b'whoami':
                response = b"\n" + b"corpuser1" + b"\r\n" # If the attacker types 'whoami', we respond with a fake user.
            elif command.strip() == b'ls':
                response = b"\n" + b"jumpbox1.conf" + b"\r\n"
            elif command.strip() == b'cat jumpbox1.conf':
                response = b"\n" + b"Go to leenaisawesome.com" + b"\r\n"
            else:
                response = b"\n" + bytes(command.strip()) + b": command not found\r\n" # For any other command, we respond with a generic "command not found" message.

            channel.send(response)
            creds_logger.info(f"{client_ip} executed command: {command.strip().decode()}") # We log the command that the attacker executed, along with their IP address, for analysis.
            channel.send(b'lolo-jumpbox2$ ') # After processing the command, we send the prompt again for the next command.
            command = b"" # We reset the command variable to capture the next command from the attacker.
# SSH Server + Sockets
class Server(paramiko.ServerInterface): # We create a class called Server that inherits from paramiko.ServerInterface. This class will handle the SSH server functionality, such as authentication and channel requests.
    def __init__(self, client_ip, input_username=None, input_password=None):
        self.event = threading.Event() # We initialize a threading event that we will use to synchronize the handling of SSH sessions and shell requests.
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password

    def check_channel_request(self, kind: str, chanid: int) -> int: # This method is called when the SSH client requests a channel. We check if the requested channel type is 'session', which is the type of channel used for interactive shell sessions. If it is, we return paramiko.OPEN_SUCCEEDED to indicate that the channel request is approved. If it's not a 'session' channel, we can choose to reject it by returning a different value (e.g., paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED).
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
    def get_allowed_auths(self, username): # Paramiko calls this with the username argument
        return 'password'
    def check_auth_password(self, username, password):
        funnel_logger.info(f"{self.client_ip} attempted to authenticate with username: {username} and password: {password}") # We log the authentication attempt, including the client's IP address, the username, and the password they used. This information is valuable for analyzing attack patterns and identifying potential threats.
        creds_logger.info(f"{self.client_ip}, {username}, {password}") 
        if self.input_username is not None and self.input_password is not None:
            if (username == self.input_username) and (password == self.input_password):
                return paramiko.AUTH_SUCCESSFUL
            else:
                return paramiko.AUTH_FAILED
        else:
            return paramiko.AUTH_SUCCESSFUL # This method is called when the SSH client attempts to authenticate using a username and password. We check if the provided username and password match the expected values (if they are set). If they match, we return paramiko.AUTH_SUCCESSFUL to indicate that authentication was successful. If they don't match, we return paramiko.AUTH_FAILED to indicate that authentication failed. If no specific username and password are set, we allow any credentials by returning paramiko.AUTH_SUCCESSFUL.    
        
    def check_channel_shell_request(self, channel):
        self.event.set() # This method is called when the SSH client requests a shell on the channel. We set an event to indicate that the shell request has been received and approved. This allows us to synchronize the handling of the shell request with the rest of our code, ensuring that we can properly manage the SSH session and respond to the attacker's commands.
        return True
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True # This method is called when the SSH client requests a pseudo-terminal (PTY) for the channel. We return True to indicate that we approve the PTY request, allowing the attacker to have an interactive shell experience when they connect to the SSH server.
    def check_channel_exec_request(self, channel, command):
        command = str(command)
        return True # This method is called when the SSH client requests to execute a command on the channel. We convert the command to a string and return True to indicate that we approve the execution request. This allows the attacker to execute commands on the honeypot, which we can log for analysis.

def client_handle(client, addr, username, password):
    client_ip = addr[0]
    print(f"{client_ip} has connected to the server.")
    try:
        
        # transport object to handle low level SSH session
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER
        server = Server(client_ip = client_ip, input_username=username, input_password=password)

        transport.add_server_key(host_key)
        transport.start_server(server=server)

        channel = transport.accept(100)
        if channel is None:
            print("No channel was opened.")
        standard_banner = "Welcome to the lolo jumpbox!\r\n\r\n"
        channel.send(standard_banner.encode())
        emulated_shell(channel, client_ip=client_ip)

    except Exception as error:
        print(error)
        print("!!! ERROR !!!")
    finally:
        try:
            transport.close()
        except Exception as error:
            print(error)
            print("!!! ERROR !!!")
# Provision SSH-based Honeypot

def honeypot(address, port, username, password):
    socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)# Ipv4, TCP socket
    socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # This line sets the socket option SO_REUSEADDR to allow the socket to be reused immediately after it is closed. This is useful for development and testing purposes, as it allows us to quickly restart the honeypot without waiting for the operating system to release the port.
    socks.bind((address, port)) # We bind the socket to the specified address and port

    socks.listen(100)
    print(f"[*] SSH Honeypot is listening on {address}:{port}...")

    while True:
        try:
            client, addr = socks.accept() # We wait for incoming connections to the honeypot. When a client connects, we accept the connection and get the client's socket and address information.
            ssh_honeypot_thred = threading.Thread(target=client_handle, args=(client, addr, username, password)) # We create a new thread to handle the client's connection. This allows us to handle multiple connections simultaneously without blocking the main thread of the honeypot.
            ssh_honeypot_thred.start() # We start the thread to handle the client's connection.
        
        except Exception as error:
            print(error)
        
honeypot('127.0.0.1', 2223, username=None, password=None) # We call the honeypot function to start the SSH honeypot on the specified address and port. We can optionally provide a specific username and password for authentication, or allow any credentials by passing None.