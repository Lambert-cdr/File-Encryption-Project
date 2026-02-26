import asyncio
import json
import websockets

# Store connected websockets and user public keys
clients = {}
public_keys = {} # Format: {"username": "public_key_hex_string"}

async def chat_handler(websocket):
    username = None
    try:
        async for message in websocket:
            data = json.loads(message)
            action = data.get("action")

            # 1. User Registration
            if action == "register":
                username = data.get("username")
                pub_key = data.get("public_key")
                
                clients[username] = websocket
                public_keys[username] = pub_key
                print(f"[+] {username} registered with Public Key: {pub_key[:10]}...")
                
            # 2. Key Exchange Request (Send target's public key to the requester)
            elif action == "get_public_key":
                target_user = data.get("target")
                target_pub_key = public_keys.get(target_user)
                
                if target_pub_key:
                    await websocket.send(json.dumps({
                        "action": "public_key_response",
                        "target": target_user,
                        "public_key": target_pub_key
                    }))
                else:
                    await websocket.send(json.dumps({
                        "error": f"Public key for {target_user} not found."
                    }))

            # 3. Message Routing
            elif action == "send_message":
                target_user = data.get("to")
                encrypted_payload = data.get("payload")
                
                if target_user in clients:
                    target_ws = clients[target_user]
                    await target_ws.send(json.dumps({
                        "action": "incoming_message",
                        "from": username,
                        "payload": encrypted_payload
                    }))
                    # Print the payload to prove the server can't read it
                    print(f"[>] Routed encrypted packet from {username} to {target_user}")
                    print(f"    Payload looks like: {encrypted_payload[:20]}...")
                else:
                    await websocket.send(json.dumps({"error": f"{target_user} is offline."}))
                    
    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        if username and username in clients:
            del clients[username]
            del public_keys[username]
            print(f"[-] {username} disconnected.")

async def main():
    async with websockets.serve(chat_handler, "0.0.0.0", 8765):
        print("E2EE WebSocket Server running on port 8765...")
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())