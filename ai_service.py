import os
import google.generativeai as genai
from dotenv import load_dotenv

# .env dosyasını yükle
load_dotenv()

# API Anahtarını al
API_KEY = os.getenv("GEMINI_API_KEY")

class GeminiService:
    def __init__(self):
        if not API_KEY:
            print("UYARI: GEMINI_API_KEY bulunamadı. Yapay zeka özellikleri çalışmayacak.")
            self.model = None
            return

        try:
            genai.configure(api_key=API_KEY)
            self.model = genai.GenerativeModel('gemini-2.5-flash')
        except Exception as e:
            print(f"Gemini başlatma hatası: {e}")
            self.model = None

    def recommend_books(self, student_history, all_books_context):
        """
        Öğrenci okuma geçmişine göre kitap önerir.
        
        Args:
            student_history (list): Öğrencinin okuduğu kitapların listesi (isimler).
            all_books_context (list): Kütüphanedeki mevcut kitapların listesi (isimler).
        
        Returns:
            list: Önerilen kitap isimleri veya açıklama.
        """
        if not self.model:
            return ["Yapay zeka servisi aktif değil."]

        prompt = f"""
        Aşağıdaki öğrenci okuma geçmişine dayanarak, kütüphanedeki mevcut kitaplardan 3 tane öneri yap.
        
        Öğrencinin Okudukları: {', '.join(student_history) if student_history else 'Henüz hiç kitap okumamış.'}
        
        Kütüphanedeki Mevcut Kitaplar: {', '.join(all_books_context)[:1000]}... (Listeden seç)
        
        Yanıtı sadece JSON formatında ver: {{"oneriler": ["Kitap 1", "Kitap 2", "Kitap 3"], "neden": "Kısaca neden önerildiği"}}
        Lütfen Türkçe yanıt ver.
        """
        
        try:
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            return f"Öneri alınırken hata oluştu: {str(e)}"

    def summarize_book(self, book_title, author):
        """
        Kitap ismi ve yazar bilgisine göre kısa özet çıkarır.
        """
        if not self.model:
            return "Yapay zeka servisi aktif değil."

        prompt = f"""
        '{book_title}' adlı kitap (Yazarı: {author}) için 2-3 cümlelik çok kısa, ilgi çekici bir Türkçe özet yaz.
        
        ÖNEMLİ KURALLAR:
        1. Sadece özeti yaz. Başlık, 'Seçenek 1' gibi metinler, yıldız (*) veya markdown işaretleri KULLANMA.
        2. Tek bir paragraf olsun.
        3. Öğrencilerin ilgisini çekecek samimi bir dil kullan.
        """
        
        try:
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            return f"Özet oluşturulurken hata: {str(e)}"
