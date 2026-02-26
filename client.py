import asyncio
import json
import websockets
from nacl.public import PrivateKey, PublicKey, Box
from nacl.encoding import HexEncoder

# Dictionary to cache the public keys of people we chat with
peer_keys = {}

# --- DIFFIE-HELLMAN KEY GENERATION ---
# Generate a new private key and derive the public key automatically
my_private_key = PrivateKey.generate()
# We convert it to HEX string to safely send it over JSON
my_public_key_hex = my_private_key.public_key.encode(encoder=HexEncoder).decode('utf-8')

async def receive_messages(websocket):
    """Listens for incoming messages and public key responses."""
    try:
        async for message in websocket:
            data = json.loads(message)
            
            if "error" in data:
                print(f"\n[!] Error: {data['error']}")
                continue
                
            action = data.get("action")
            
            # Save the public key if the server sends it
            if action == "public_key_response":
                target = data.get("target")
                pub_key_hex = data.get("public_key")
                # Convert HEX string back to PublicKey object
                peer_keys[target] = PublicKey(pub_key_hex.encode('utf-8'), encoder=HexEncoder)
                print(f"\n[*] Received Public Key for {target}. You can now send messages.")

            # Receive and DECRYPT incoming messages
            elif action == "incoming_message":
                sender = data.get("from")
                encrypted_hex = data.get("payload")
                
                if sender not in peer_keys:
                    print(f"\n[!] Received encrypted message from {sender}, but we don't have their public key to decrypt it!")
                    continue
                    
                # Create a Box using MY Private Key + SENDER'S Public Key (Diffie-Hellman!)
                crypto_box = Box(my_private_key, peer_keys[sender])
                
                try:
                    # Convert HEX back to bytes and decrypt
                    encrypted_bytes = HexEncoder.decode(encrypted_hex)
                    decrypted_message = crypto_box.decrypt(encrypted_bytes).decode('utf-8')
                    print(f"\n[🔒 E2EE] {sender}: {decrypted_message}")
                except Exception as e:
                    print(f"\n[!] Failed to decrypt message from {sender}: {e}")
                    
    except websockets.exceptions.ConnectionClosed:
        print("\n[!] Connection lost.")

async def send_messages(websocket, username):
    """Handles user input, encrypts the message, and sends it."""
    while True:
        user_input = await asyncio.to_thread(input, "")
        if not user_input.strip() or ":" not in user_input:
            continue
            
        target_user, plaintext_message = user_input.split(":", 1)
        target_user = target_user.strip()
        plaintext_message = plaintext_message.strip()
        
        # 1. Do we have the target's public key? If not, ask the server.
        if target_user not in peer_keys:
            print(f"[*] Requesting public key for {target_user}...")
            await websocket.send(json.dumps({
                "action": "get_public_key",
                "target": target_user
            }))
            # Wait a bit for the server to respond before trying to send the message
            await asyncio.sleep(0.5)
            
            if target_user not in peer_keys:
                print(f"[!] Could not get public key for {target_user}. Message not sent.")
                continue

        # 2. We have the key! ENCRYPT the message.
        # Create a Box using MY Private Key + TARGET'S Public Key
        crypto_box = Box(my_private_key, peer_keys[target_user])
        
        # Encrypt the plaintext (returns bytes)
        encrypted_bytes = crypto_box.encrypt(plaintext_message.encode('utf-8'))
        # Convert encrypted bytes to HEX string for JSON
        encrypted_hex = HexEncoder.encode(encrypted_bytes).decode('utf-8')
        
        # 3. Send the ENCRYPTED payload to the server
        await websocket.send(json.dumps({
            "action": "send_message",
            "to": target_user,
            "payload": encrypted_hex
        }))

async def main():
    server_url = "ws://localhost:8765" 
    username = input("Enter your username: ")
    
    try:
        async with websockets.connect(server_url) as websocket:
            print(f"\n[+] Connected as '{username}'.")
            
            # Send our Public Key to the server upon registration
            await websocket.send(json.dumps({
                "action": "register",
                "username": username,
                "public_key": my_public_key_hex
            }))
            
            receive_task = asyncio.create_task(receive_messages(websocket))
            send_task = asyncio.create_task(send_messages(websocket, username))
            
            await asyncio.gather(receive_task, send_task)
            
    except ConnectionRefusedError:
        print("[!] Connection failed.")

if __name__ == "__main__":
    asyncio.run(main())