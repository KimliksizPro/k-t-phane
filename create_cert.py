
from OpenSSL import crypto
import socket
import os

def generate_ca():
    # 1. Generate CA Key
    ca_key = crypto.PKey()
    ca_key.generate_key(crypto.TYPE_RSA, 2048)

    # 2. Generate CA Certificate
    ca_cert = crypto.X509()
    ca_cert.get_subject().C = "TR"
    ca_cert.get_subject().O = "Kutuphane Yerel CA"
    ca_cert.get_subject().CN = "Kutuphane Root CA"
    ca_cert.set_serial_number(1001)
    ca_cert.gmtime_adj_notBefore(0)
    ca_cert.gmtime_adj_notAfter(10*365*24*60*60)
    ca_cert.set_issuer(ca_cert.get_subject())
    ca_cert.set_pubkey(ca_key)
    
    # CA Extensions
    ca_cert.add_extensions([
        crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE, pathlen:0"),
        crypto.X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"),
        crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=ca_cert),
    ])
    
    ca_cert.sign(ca_key, 'sha256')
    return ca_key, ca_cert

def generate_server_cert(ca_key, ca_cert):
    # 1. Generate Server Key
    server_key = crypto.PKey()
    server_key.generate_key(crypto.TYPE_RSA, 2048)
    
    # 2. Generate Server Certificate
    server_cert = crypto.X509()
    server_cert.get_subject().C = "TR"
    server_cert.get_subject().O = "Kutuphane Yonetim Sistemi"
    server_cert.get_subject().CN = "localhost"
    server_cert.set_serial_number(1002)
    server_cert.gmtime_adj_notBefore(0)
    server_cert.gmtime_adj_notAfter(10*365*24*60*60)
    server_cert.set_issuer(ca_cert.get_subject())
    server_cert.set_pubkey(server_key)
    
    # SANs
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
    except:
        local_ip = "127.0.0.1"
        
    san_list = [
        "DNS:localhost",
        "IP:127.0.0.1",
        f"IP:{local_ip}"
    ]
    san_str = ", ".join(san_list).encode("utf-8")
    
    server_cert.add_extensions([
        crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
        crypto.X509Extension(b"keyUsage", True, b"digitalSignature, keyEncipherment"),
        crypto.X509Extension(b"subjectAltName", False, san_str),
        crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always", issuer=ca_cert)
    ])
    
    server_cert.sign(ca_key, 'sha256')
    return server_key, server_cert

def main():
    print("Sertifika otoritesi olusturuluyor...")
    ca_key, ca_cert = generate_ca()
    
    print("Sunucu sertifikasi imzalanior...")
    server_key, server_cert = generate_server_cert(ca_key, ca_cert)
    
    # Save Root CA (To be installed by user)
    with open("root_ca.crt", "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert).decode("utf-8"))
        
    # Save Server Cert/Key (Used by App)
    with open("cert.pem", "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, server_cert).decode("utf-8"))
    with open("key.pem", "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, server_key).decode("utf-8"))

    print("ISLEM TAMAM!")
    print("1. 'root_ca.crt' dosyasi olusturuldu. -> Windows'a TANITILACAK OLAN BU.")
    print("2. 'cert.pem' ve 'key.pem' olusturuldu. -> Uygulama bunlari kullanacak.")

if __name__ == "__main__":
    main()
