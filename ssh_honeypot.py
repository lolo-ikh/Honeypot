# for more info on SSH: check this youtube video: https://www.youtube.com/watch?v=P0Fk-K2eZF8
# i have created server.key and sever.key.pub using the command: ssh-keygen -t rsa -b 2048 -f server.key
# Libraries
import logging
from logging.handlers import RotatingFileHandler
import socket
import paramiko # Paramiko is a Python library that provides an implementation of the SSHv2 protocol, allowing us to create an SSH server and handle SSH connections.
# Constants
logging_format = logging.Formatter('%(message)s')
SSH_BANNER = "SSH-2.0-MySSHServer_1.0" # This is the banner that the SSH server will present to clients when they connect. It identifies the server and its version.
host_key = 'server.key' # This is the path to the private key file that the SSH server will use for authentication. The private key is essential for establishing secure SSH connections.


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
        channel.send(b'lolo-jumpbox2$ ') # After processing the command, we send the prompt again for the next command.
        command = b"" # We reset the command variable to capture the next command from the attacker.
# SSH Server + Sockets
class Server(paramiko.ServerInterface): # We create a class called Server that inherits from paramiko.ServerInterface. This class will handle the SSH server functionality, such as authentication and channel requests.
    def __init__(self, client_ip, input_username=None, input_password=None):
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password

    def check_channel_request(self, kind: str, chanid: int) -> int: # This method is called when the SSH client requests a channel. We check if the requested channel type is 'session', which is the type of channel used for interactive shell sessions. If it is, we return paramiko.OPEN_SUCCEEDED to indicate that the channel request is approved. If it's not a 'session' channel, we can choose to reject it by returning a different value (e.g., paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED).
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
    def get_allowed_auths(self): # This method is called to determine which authentication methods are allowed for the SSH server. In this case, we return 'password', indicating that we only allow password-based authentication. This means that when an attacker tries to connect to the SSH server, they will be prompted to enter a password for authentication.
        return 'password'
    def check_auth_password(self, username, password):
        if self.input_username is not None and self.input_password is not None:
            if (username == self.input_username) and (password == self.input_password):
                return paramiko.AUTH_SUCCESSFUL
            else:
                return paramiko.AUTH_FAILED
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
        transport = paramiko.Transport()
        transport.local_version = SSH_BANNER
        server = Server(client_ip = client_ip, input_username=username, input_password=password)

        transport.add_server_key(host_key)
        transport.start_server(server=server)

        channel = transport.accept(100)
        if channel is None:
            print("No channel was opened.")
        standard_banner = "Welcome to the lolo jumpbox!\r\n\r\n"
        channel.send(standard_banner)
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