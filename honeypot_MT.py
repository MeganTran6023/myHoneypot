#1 - imports
import socket
import logging
import paramiko
from threading import Thread, Event

# 2 - Logging attackers in .txt file
logging.basicConfig(
    log_file="honeypot.log",
    level=logging.INFO,
    log_format="%(asctime)s - IP: %(message)s",
)

#3 - load host key

## this verifies the host server's identity to ensure secure SSH connections
host_key = paramiko.RSAKey(filename="host_key")

#4- SSH server class

## this includes all the operations done when user connects
## with the histed server

##I specified for the server to allow the user to "log in"
## after 3 times to deter them even though we collected data from attackers the first time

class BasicHoneypot(paramiko.ServerInterface):
##initializing
    def __init__(self, client_ip):
            self.client_ip = client_ip
            self.event = Event() 
            self.login_attempts = 0
            
##verify password. 3 attempts allow
    def check_auth_password(self,username,password):
        #track logging in attempt
        logging.info(f"{self.client_ip} | Username: {username} | Password: {password}")
        print(f"Login attempt: IP: {self.client_ip} | Username: {username} | Password: {password}")
        
        #counter
        self.login_attempts += 1
        
        #send fake welcome message after 3rd attempt
        if self.login_attempts >= 3:
            self.event.set()  # Signal the channel to open
            return paramiko.AUTH_SUCCESSFUL
        
        #fake failed attempt in previous attempts
        return paramiko.AUTH_FAILED
    
    #authenticate after provided user
    def get_allowed_auths(self, username):
        return "password"
    
    #only allow one specific session
    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    #open up "shell" after 3rd attempt
    def check_channel_shell_request(self, channel):
        if self.login_attempts == 3:
             return True
        return False
    
    #5 - Client handling (messages show on python terminal)
def handle_client(client,addr):
    #extract ip
    client_ip = addr[0]
    print(f"[+] Connection from {client_ip}")
    
    #connecting user to server using class
    try:
        transport = paramiko.Transport(client)
        transport.add_server_key(host_key)
        transport.local_version = "SSH-2.0-Honeypot"
        server = BasicHoneypot(client_ip = client_ip)
        
        try:
            transport.start_server(server=server)
            
        except paramiko.SSHException as e:
            print(f"[-] SSH negotiation failed with {client_ip}: {e}")
            return
        
        #wait for client input for up to 20 seconds
        channel = transport.accept(20)
        if channel is None:
            print(f"[-] No channel established with {client_ip}")
            return
        
        #fake welcome message after 3rd attempt
        if server.login_attempts == 3:
            print(f"Welcom to SSH Honeypot!")
            return
        
        channel.close()
    except:
        print(f"[-] Exception handling client {client_ip}: {e}")
    finally:
        channel.close()
        
    #6- main function for initiating honeypot
def start_honeypot(host="0.0.0.0", port = 2222):
    #receives incoming connections to server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR)#reusability
    server_socket.bind((host,port))
    server_socket.listen(20)
    
    print(f"[+] Honeypot is running on {host}:{port}")
    
    #handle multiple clients - threading
    try:
        while True:
            client, addr = server_socket.accept()
            Thread(target=handle_client, args=(client, addr)) 
    except KeyboardInterrupt:
        print("\n[!] Shutting down the honeypot.")
    finally:
        server_socket.close()
        
    #call main function
    if __name__ == "__main__":
        start_honeypot()