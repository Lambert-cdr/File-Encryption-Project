import socket
import threading
import json
from colorama import init, Fore, Style
from datetime import datetime

# Initialize colorama for colored terminal output
init(autoreset=True)

HOST = '0.0.0.0'
PORT = 16261

clients = {}  # Format: {username: socket_object}
clients_lock = threading.Lock()

def log(level, message):
    time_str = datetime.now().strftime('%H:%M:%S')
    if level == "INFO":
        print(f"[{Fore.CYAN}{time_str}{Style.RESET_ALL}] [{Fore.GREEN}INFO{Style.RESET_ALL}] {message}")
    elif level == "WARN":
        print(f"[{Fore.CYAN}{time_str}{Style.RESET_ALL}] [{Fore.YELLOW}WARN{Style.RESET_ALL}] {message}")
    elif level == "ROUTE":
        print(f"[{Fore.CYAN}{time_str}{Style.RESET_ALL}] [{Fore.MAGENTA}ROUTE{Style.RESET_ALL}] {message}")
    elif level == "ERROR":
        print(f"[{Fore.CYAN}{time_str}{Style.RESET_ALL}] [{Fore.RED}ERROR{Style.RESET_ALL}] {message}")

def broadcast_user_list():
    with clients_lock:
        user_list = list(clients.keys())
        msg = json.dumps({"type": "USERS", "users": user_list}) + "\n"
        for user, conn in clients.items():
            try:
                conn.sendall(msg.encode('utf-8'))
            except Exception as e:
                log("ERROR", f"Failed to send user list to {user}: {e}")

def handle_client(conn, addr):
    username = None
    try:
        # First message must be LOGIN
        data = conn.recv(1024).decode('utf-8')
        if not data:
            return
            
        msg = json.loads(data.strip())
        if msg.get("type") == "LOGIN":
            username = msg.get("username")
            with clients_lock:
                if username in clients:
                    conn.sendall(json.dumps({"type": "ERROR", "message": "Username already taken."}).encode('utf-8') + b'\n')
                    return
                clients[username] = conn
            
            log("INFO", f"User '{username}' connected from {addr}.")
            broadcast_user_list()
        
        # Listen for routed messages
        buffer = ""
        while True:
            chunk = conn.recv(4096).decode('utf-8')
            if not chunk:
                break
                
            buffer += chunk
            while '\n' in buffer:
                line, buffer = buffer.split('\n', 1)
                if not line.strip(): continue
                
                packet = json.loads(line)
                target_user = packet.get("to")
                
                if target_user:
                    with clients_lock:
                        target_conn = clients.get(target_user)
                        
                    if target_conn:
                        packet_type = packet.get("type", "UNKNOWN")
                        if packet_type != "FILE_CHUNK": # Don't log every single chunk to avoid spam
                            log("ROUTE", f"[{packet_type}] from {username} -> {target_user}")
                            
                        target_conn.sendall((json.dumps(packet) + "\n").encode('utf-8'))
                    else:
                        error_msg = json.dumps({"type": "ERROR", "message": f"User '{target_user}' is not connected."}) + "\n"
                        conn.sendall(error_msg.encode('utf-8'))
                        log("WARN", f"{username} tried to send to disconnected user '{target_user}'.")

    except Exception as e:
        log("ERROR", f"Connection error with {username or addr}: {e}")
    finally:
        if username:
            with clients_lock:
                if username in clients:
                    del clients[username]
            log("WARN", f"User '{username}' disconnected.")
            broadcast_user_list()
        conn.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    log("INFO", f"Server started and listening on {HOST}:{PORT}")
    
    try:
        while True:
            conn, addr = server.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr))
            thread.daemon = True
            thread.start()
    except KeyboardInterrupt:
        log("INFO", "Server shutting down.")
    finally:
        server.close()

if __name__ == "__main__":
    start_server()
