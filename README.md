# File-Encryption-Project

## 🔧 Bileşenler

### File Crypting and Key Production.py
- Dosyaları şifrelemek için gerekli fonksiyonları içerir
- RSA ve Fernet anahtarlarını üretir ve yönetir
- Şifreleme/deşifreleme işlemlerini gerçekleştirir

### client.py
- Kullanıcı arayüzü sağlayan istemci uygulaması
- Sunucuya bağlanarak dosya işlemleri gerçekleştirir
- Şifreleme/deşifreleme taleplerini sunucuya gönderir

### server.py
- Merkezi sunucu uygulaması
- İstemci isteklerini karşılar
- Dosya şifreleme işlemlerini yönetir
- Anahtarları merkezi olarak saklar

## 🚀 Kullanım

### Gereksinimler
- Python 3.x
- Gerekli kütüphaneler (cryptography, vb.)

### Başlama

1. **Sunucuyu Başlat**
```bash
python server.py
