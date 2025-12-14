import random
from app import app, db, Student, Book

def create_test_data():
    print("Creating test data...")
    
    # Test Students
    first_names = ["Ahmet", "Mehmet", "Ayşe", "Fatma", "Ali", "Veli", "Zeynep", "Mustafa", "Elif", "Can"]
    last_names = ["Yılmaz", "Kaya", "Demir", "Çelik", "Şahin", "Yıldız", "Özdemir", "Arslan", "Doğan", "Kılıç"]
    classes = ["9-A", "9-B", "10-A", "10-B", "11-A", "11-B", "12-A", "12-B"]
    
    for i in range(15):
        name = random.choice(first_names)
        surname = random.choice(last_names)
        school_number = str(random.randint(100, 9999))
        
        # Check if student exists
        if not Student.query.filter_by(school_number=school_number).first():
            student = Student(
                name=name,
                surname=surname,
                school_number=school_number,
                class_name=random.choice(classes),
                email=f"{name.lower()}.{surname.lower()}{i}@example.com",
                phone=f"555{random.randint(1000000, 9999999)}"
            )
            db.session.add(student)
            print(f"Added student: {name} {surname}")

    # Test Books
    book_titles = ["Sefiller", "Suç ve Ceza", "Vadideki Zambak", "Çalıkuşu", "Kürk Mantolu Madonna", 
                   "Simyacı", "1984", "Hayvan Çiftliği", "Satranç", "Dönüşüm", 
                   "Beyaz Diş", "Martin Eden", "Nutuk", "Safahat", "İnce Memed"]
    authors = ["Victor Hugo", "Dostoyevski", "Balzac", "Reşat Nuri Güntekin", "Sabahattin Ali",
               "Paulo Coelho", "George Orwell", "George Orwell", "Stefan Zweig", "Franz Kafka",
               "Jack London", "Jack London", "Mustafa Kemal Atatürk", "Mehmet Akif Ersoy", "Yaşar Kemal"]
    
    for i in range(15):
        title = book_titles[i] if i < len(book_titles) else f"Kitap {i}"
        author = authors[i] if i < len(authors) else f"Yazar {i}"
        isbn = f"978-{random.randint(1000000000, 9999999999)}"
        
        if not Book.query.filter_by(isbn=isbn).first():
            book = Book(
                title=title,
                author=author,
                isbn=isbn,
                publication_year=str(random.randint(1900, 2023)),
                publisher="Test Yayınları",
                category="Roman",
                description="Test açıklaması..."
            )
            db.session.add(book)
            print(f"Added book: {title}")

    try:
        db.session.commit()
        print("Database populated successfully!")
    except Exception as e:
        db.session.rollback()
        print(f"Error: {e}")

if __name__ == "__main__":
    with app.app_context():
        create_test_data()
