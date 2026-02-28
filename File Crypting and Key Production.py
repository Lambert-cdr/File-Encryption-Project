# ========= ŞİFRELEME UYGULAMAMIZIN DOSYA OLUŞTURMA VE ANAHTARLAMA KISMI =========
import os
import json
import time
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# ========== DIFFIE-HELLMAN ANAHTAR ÜRETİMİ ==========
parameters = dh.generate_parameters(generator=2, key_size=2048)
private_key_sender = parameters.generate_private_key()
private_key_receiver = parameters.generate_private_key()

public_key_sender = private_key_sender.public_key()
public_key_receiver = private_key_receiver.public_key()

shared_key_sender = private_key_sender.exchange(public_key_receiver)

# HKDF ile AES anahtarı türetme
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data',
).derive(shared_key_sender)

# ========== DOSYA ŞİFRELEME ==========
def dosya_sifrele(dosya):
    if not os.path.exists(dosya):
        print(f"Hata: {dosya} bulunamadı!")
        return False
    
    with open(dosya, "rb") as f:
        veri = f.read()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(veri) + padder.finalize()

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    with open(dosya + ".enc", "wb") as f:
        f.write(iv + ciphertext)
    return True

# ========== DOSYA ÇÖZME ==========
def dosya_coz(dosya):
    if not os.path.exists(dosya):
        print(f"Hata: {dosya} bulunamadı!")
        return False

    with open(dosya, "rb") as f:
        veri = f.read()

    iv = veri[:16]
    ciphertext = veri[16:]

    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plain = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plain = unpadder.update(padded_plain) + unpadder.finalize()

    with open("cozulmus.txt", "wb") as f:
        f.write(plain)
    return True

# ========== LOG ==========
def log_kaydet(dosya, islem):
    if os.path.exists(dosya):
        log = {
            "Dosya": dosya,
            "İşlem": islem,
            "Zaman": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Boyut(byte)": os.path.getsize(dosya)
        }
        with open("log.txt", "a") as f:
            f.write(json.dumps(log) + "\n")

# ========== TEST (Önce test dosyası oluşturuyoruz) ==========
test_dosyasi = "metin.txt"
with open(test_dosyasi, "w") as f:
    f.write("Bu bir gizli mesajdir.")

if dosya_sifrele(test_dosyasi):
    log_kaydet(test_dosyasi, "Şifrelendi")
    print("Dosya şifrelendi.")

    time.sleep(2)

    if dosya_coz(test_dosyasi + ".enc"):
        log_kaydet(test_dosyasi + ".enc", "Çözüldü")
        print("Dosya çözüldü, 'cozulmus.txt' oluşturuldu.")


