import socket
import threading
import json
import base64
import os
import time
from tqdm import tqdm
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

HOST = '213.14.151.25'  # Change this to the Server's IP address
PORT = 16261        # Make sure this matches the server port

class FileShareClient:
    def __init__(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.username = ""
        self.connected_users = []
        self.is_transferring = False
        self.pending_offer = None  # Tracks if someone is waiting for our approval
        
        # Crypto elements
        self.private_key = ec.generate_private_key(ec.SECP384R1())
        self.public_key = self.private_key.public_key()
        
        # Transfer states
        self.receive_file = None
        self.receive_pbar = None
        self.receive_fernet = None
        
        self.send_lock = threading.Lock()

    def get_public_key_bytes(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

    def derive_shared_key(self, peer_public_key_pem):
        peer_public_key = serialization.load_pem_public_key(peer_public_key_pem.encode('utf-8'))
        shared_secret = self.private_key.exchange(ec.ECDH(), peer_public_key)
        
        # Derive a 32-byte key for Fernet (AES) using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'file_share_handshake',
        ).derive(shared_secret)
        
        return base64.urlsafe_b64encode(derived_key)

    def send_packet(self, packet):
        try:
            msg = json.dumps(packet) + "\n"
            self.client_socket.sendall(msg.encode('utf-8'))
        except Exception as e:
            print(f"\n[ERROR] Failed to send data: {e}")

    def listen_to_server(self):
        buffer = ""
        while True:
            try:
                chunk = self.client_socket.recv(4096).decode('utf-8')
                if not chunk:
                    break
                buffer += chunk
                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    if not line.strip(): continue
                    self.handle_server_message(json.loads(line))
            except Exception as e:
                print(f"\n[ERROR] Connection lost: {e}")
                break

    def handle_server_message(self, msg):
        msg_type = msg.get("type")

        if msg_type == "USERS":
            self.connected_users = [u for u in msg.get("users") if u != self.username]
            if not self.is_transferring and not self.pending_offer:
                self.print_menu()

        elif msg_type == "ERROR":
            print(f"\n[SERVER ERROR] {msg.get('message')}")
            self.is_transferring = False

        elif msg_type == "FILE_OFFER":
            # Someone wants to send us a file, show the prompt
            self.pending_offer = msg
            print(f"\n\n>>> [INCOMING REQUEST] User '{msg.get('from')}' wants to send you a file:")
            print(f"    File: {msg.get('filename')} ({msg.get('filesize')} bytes)")
            print(">>> Type '/y' to accept or '/n' to reject and press Enter.")

        elif msg_type == "OFFER_RESPONSE":
            # The person we sent an offer to has responded
            if msg.get("accepted"):
                print(f"\n[INFO] {msg.get('from')} accepted! Starting encrypted transfer...")
                receiver_pub_key = msg.get("pubkey")
                shared_key = self.derive_shared_key(receiver_pub_key)
                fernet = Fernet(shared_key)
                
                # Start sending file thread
                threading.Thread(target=self.transmit_file, args=(msg.get("from"), self.current_sending_file, fernet)).start()
            else:
                print(f"\n[DECLINED] {msg.get('from')} rejected your file transfer.")
                self.is_transferring = False
                time.sleep(1.5)
                self.print_menu()

        elif msg_type == "FILE_CHUNK":
            if self.receive_fernet and self.receive_file:
                encrypted_data = base64.b64decode(msg.get("data").encode('utf-8'))
                decrypted_data = self.receive_fernet.decrypt(encrypted_data)
                self.receive_file.write(decrypted_data)
                self.receive_pbar.update(len(decrypted_data))

        elif msg_type == "FILE_END":
            if self.receive_file:
                self.receive_file.close()
                self.receive_pbar.close()
                print(f"\n[SUCCESS] File received successfully from {msg.get('from')}!")
                self.is_transferring = False
                time.sleep(1.5)
                self.print_menu()

    def transmit_file(self, target, filepath, fernet):
        filesize = os.path.getsize(filepath)
        filename = os.path.basename(filepath)
        
        with open(filepath, 'rb') as f:
            with tqdm(total=filesize, desc="Sending", unit="B", unit_scale=True) as pbar:
                while True:
                    # Read chunk (32KB)
                    chunk = f.read(32768)
                    if not chunk:
                        break
                        
                    # Encrypt and encode
                    encrypted_chunk = fernet.encrypt(chunk)
                    encoded_chunk = base64.b64encode(encrypted_chunk).decode('utf-8')
                    
                    self.send_packet({
                        "type": "FILE_CHUNK",
                        "to": target,
                        "from": self.username,
                        "data": encoded_chunk
                    })
                    pbar.update(len(chunk))
        
        self.send_packet({
            "type": "FILE_END",
            "to": target,
            "from": self.username
        })
        print(f"\n[SUCCESS] File '{filename}' sent to {target} successfully!")
        self.is_transferring = False
        time.sleep(1.5)
        self.print_menu()

    def print_menu(self):
        if self.is_transferring or self.pending_offer:
            return
            
        os.system('cls' if os.name == 'nt' else 'clear')
        print("========================================")
        print(f" Logged in as: [{self.username}]")
        print("========================================")
        print(" Available Users:")
        if not self.connected_users:
            print("  (No other users connected right now)")
        else:
            for user in self.connected_users:
                print(f"  - {user}")
        print("========================================")
        print(" Type target username to share a file, or 'exit'.\n")

    def start(self):
        self.username = input("Enter your username: ").strip()
        
        try:
            self.client_socket.connect((HOST, PORT))
            self.send_packet({"type": "LOGIN", "username": self.username})
        except Exception as e:
            print(f"Could not connect to server: {e}")
            return

        # Start listening thread
        listen_thread = threading.Thread(target=self.listen_to_server)
        listen_thread.daemon = True
        listen_thread.start()

        time.sleep(0.5) 
        
        while True:
            # Block interactions if a file is actively uploading/downloading
            if self.is_transferring and not self.pending_offer:
                time.sleep(1)
                continue
                
            try:
                # Handle Accept/Reject logic if an offer is waiting
                if self.pending_offer:
                    target = input("").strip().lower()
                    
                    if target == '/y':
                        sender = self.pending_offer["from"]
                        filename = self.pending_offer["filename"]
                        filesize = self.pending_offer["filesize"]
                        
                        # Lock UI and setup encryption/file writing
                        self.is_transferring = True
                        shared_key = self.derive_shared_key(self.pending_offer["pubkey"])
                        self.receive_fernet = Fernet(shared_key)
                        
                        safe_filename = "received_" + os.path.basename(filename)
                        self.receive_file = open(safe_filename, 'wb')
                        self.receive_pbar = tqdm(total=filesize, desc="Receiving", unit="B", unit_scale=True)
                        
                        self.send_packet({
                            "type": "OFFER_RESPONSE",
                            "to": sender,
                            "from": self.username,
                            "accepted": True,
                            "pubkey": self.get_public_key_bytes()
                        })
                        self.pending_offer = None
                        
                    elif target == '/n':
                        self.send_packet({
                            "type": "OFFER_RESPONSE",
                            "to": self.pending_offer["from"],
                            "from": self.username,
                            "accepted": False
                        })
                        self.pending_offer = None
                        print("[INFO] You rejected the file.")
                        time.sleep(1.5)
                        self.print_menu()
                    else:
                        print(">>> Invalid input. Please type '/y' to accept or '/n' to reject.")
                    continue

                # Standard Sending Logic
                target = input("Target user: ").strip()
                
                if self.is_transferring or self.pending_offer: continue 
                if not target: continue
                if target.lower() == 'exit': break
                
                if target not in self.connected_users:
                    print(f"[ERROR] User '{target}' is not connected or doesn't exist.")
                    time.sleep(2)
                    self.print_menu()
                    continue

                filepath = input("Enter file path/name to send (e.g. test.jpg): ").strip()
                if not os.path.exists(filepath):
                    print(f"[ERROR] File '{filepath}' not found!")
                    time.sleep(2)
                    self.print_menu()
                    continue

                # Lock the UI and store the file we want to send
                self.is_transferring = True
                self.current_sending_file = filepath
                
                filesize = os.path.getsize(filepath)
                filename = os.path.basename(filepath)
                
                # Send FILE_OFFER to target
                self.send_packet({
                    "type": "FILE_OFFER",
                    "from": self.username,
                    "to": target,
                    "filename": filename,
                    "filesize": filesize,
                    "pubkey": self.get_public_key_bytes()
                })
                print(f"\n[INFO] Sent file offer to {target}. Waiting for them to accept...")
                
            except KeyboardInterrupt:
                break
                
        self.client_socket.close()

if __name__ == "__main__":
    client = FileShareClient()
    client.start()
