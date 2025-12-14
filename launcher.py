"""
Kütüphane Otomasyon Sistemi Başlatıcı
Bu script Flask sunucusunu başlatır ve web tarayıcısında otomatik açar
"""
import os
import sys
import time
import webbrowser
import subprocess
from threading import Thread, Event
import socket

def find_free_port():
    """Boş bir port bulur"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        s.listen(1)
        port = s.getsockname()[1]
    return port

def check_server_running(port, max_attempts=30):
    """Sunucunun çalışıp çalışmadığını kontrol eder"""
    for i in range(max_attempts):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            if result == 0:
                return True
        except:
            pass
        time.sleep(0.5)
    return False

def run_flask_server(port, ready_event):
    """Flask sunucusunu çalıştırır"""
    # Get the directory where the script is located
    if getattr(sys, 'frozen', False):
        # Running as compiled executable
        app_dir = sys._MEIPASS
    else:
        # Running as script
        app_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Change to app directory
    os.chdir(app_dir)
    
    # Import and run Flask app
    from app import app, db
    
    # Initialize database
    with app.app_context():
        db.create_all()
    
    # Signal that Flask is ready to start
    ready_event.set()
    
    # Run Flask
    app.run(host='127.0.0.1', port=port, debug=False, use_reloader=False, threaded=True)

def main():
    """Ana fonksiyon"""
    # Port belirle (varsayılan 5000)
    port = 5000
    url = f'http://127.0.0.1:{port}'
    
    print("🚀 Kütüphane Otomasyon Sistemi Başlatılıyor...")
    print(f"📡 Sunucu portu: {port}")
    
    # Flask sunucusunu ayrı thread'de başlat
    ready_event = Event()
    server_thread = Thread(target=run_flask_server, args=(port, ready_event), daemon=True)
    server_thread.start()
    
    # Wait for Flask to be ready to initialize
    ready_event.wait()
    
    print("⏳ Sunucu başlatılıyor, lütfen bekleyin...")
    
    # Sunucunun hazır olmasını bekle
    if check_server_running(port):
        print("✅ Sunucu başarıyla başlatıldı!")
        print(f"🌐 Tarayıcı açılıyor: {url}")
        time.sleep(1)  # Küçük bir bekleme
        webbrowser.open(url)
        print("\n" + "="*60)
        print("✨ Kütüphane Otomasyon Sistemi Hazır!")
        print("="*60)
        print(f"📍 Adres: {url}")
        print("⚠️  Bu pencereyi KAPATMAYIN! Uygulama çalışmaya devam ediyor.")
        print("🛑 Uygulamayı kapatmak için bu pencereyi kapatın veya CTRL+C basın.")
        print("="*60 + "\n")
        
        # Keep the main thread alive
        try:
            server_thread.join()
        except KeyboardInterrupt:
            print("\n\n🛑 Uygulama kapatılıyor...")
            sys.exit(0)
    else:
        print("❌ HATA: Sunucu başlatılamadı!")
        print("Lütfen portun başka bir uygulama tarafından kullanılmadığından emin olun.")
        input("\nÇıkmak için ENTER'a basın...")
        sys.exit(1)

if __name__ == '__main__':
    main()
