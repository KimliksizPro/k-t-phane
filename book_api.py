
import requests
import json
from bs4 import BeautifulSoup
import re

def clean_isbn_func(isbn):
    return str(isbn).replace("-", "").replace(" ", "").strip()

def fetch_orhan_aydogdu(isbn):
    """
    Fetches from https://api.orhanaydogdu.com.tr/depo/kitaplar/{ISBN}
    """
    try:
        url = f"https://api.orhanaydogdu.com.tr/depo/kitaplar/{isbn}"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if not data or 'server_error' in data: return None
            
            return {
                "title": data.get("book_name", data.get("title", "")),
                "author": data.get("author", ""),
                "publisher": data.get("publisher", ""),
                "publication_year": str(data.get("published_at", "")),
                "page_count": data.get("page_count", 0),
                "description": data.get("description", ""),
                "thumbnail_url": data.get("image", data.get("cover", "")),
                "isbn": isbn
            }
    except Exception as e:
        print(f"Orhan API Error: {e}")
    return None

def fetch_google_books(isbn):
    """
    Fetches from Google Books API
    """
    try:
        url = f"https://www.googleapis.com/books/v1/volumes?q=isbn:{isbn}"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if "items" in data and len(data["items"]) > 0:
                info = data["items"][0].get("volumeInfo", {})
                return {
                    "title": info.get("title", ""),
                    "author": ", ".join(info.get("authors", [])),
                    "publisher": info.get("publisher", ""),
                    "publication_year": info.get("publishedDate", "")[:4],
                    "page_count": info.get("pageCount", 0),
                    "description": info.get("description", ""),
                    "thumbnail_url": info.get("imageLinks", {}).get("thumbnail", ""),
                    "isbn": isbn
                }
    except Exception as e:
        print(f"Google Books API Error: {e}")
    return None

def fetch_loc(isbn):
    """
    Fetches from Library of Congress (LOC)
    https://www.loc.gov/books/?fo=json&isbn={ISBN}
    """
    try:
        url = f"https://www.loc.gov/books/?fo=json&isbn={isbn}"
        response = requests.get(url, timeout=6)
        if response.status_code == 200:
            data = response.json()
            results = data.get("results")
            if results:
                item = results[0]
                
                # Extract fields with fallback logic
                title = item.get("title", [])
                if isinstance(title, list) and title: title = title[0]
                
                contributors = item.get("contributor", [])
                author = ", ".join(contributors) if contributors else ""
                
                date = item.get("date", "")
                
                description = item.get("description", [])
                if isinstance(description, list): description = " ".join(description) # LOC descriptions are often lists
                
                # LOC thumbnails are tricky, often in 'image_url' list
                images = item.get("image_url", [])
                thumbnail = images[0] if images else ""

                return {
                    "title": str(title),
                    "author": str(author),
                    "publisher": "", # LOC often doesn't give publisher easily in summary
                    "publication_year": str(date)[:4],
                    "page_count": 0, # LOC often doesn't have page count in summary
                    "description": str(description),
                    "thumbnail_url": str(thumbnail),
                    "isbn": isbn
                }
    except Exception as e:
        print(f"LOC API Error: {e}")
    return None

def fetch_open_library(isbn):
    """
    Fetches from Open Library API.
    Tries Direct Endpoint first, then Search Endpoint (as requested).
    """
    # 1. Try Direct Endpoint (Fast)
    try:
        url = f"https://openlibrary.org/isbn/{isbn}.json"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            info = response.json()
            
            publisher = ", ".join(info.get("publishers", [])) if "publishers" in info else ""
            cover_id = info.get("covers", [])
            thumbnail = f"https://covers.openlibrary.org/b/id/{cover_id[0]}-M.jpg" if cover_id else ""

            return {
                "title": info.get("title", ""),
                "author": "", # Direct endpoint often lacks author names, returns IDs
                "publisher": publisher,
                "publication_year": info.get("publish_date", "")[:4],
                "page_count": info.get("number_of_pages", 0),
                "description": "",
                "thumbnail_url": thumbnail,
                "isbn": isbn
            }
    except Exception as e:
        print(f"OpenLibrary Direct Error: {e}")

    return None

def fetch_kitapyurdu(isbn):
    """
    Crawls Kitapyurdu search results
    """
    try:
        # 1. Search for the book
        search_url = f"https://www.kitapyurdu.com/index.php?route=product/search&filter_name={isbn}"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        res = requests.get(search_url, headers=headers, timeout=8)
        
        if res.status_code == 200:
            soup = BeautifulSoup(res.text, 'html.parser')
            
            # Check if product list exists
            product_list = soup.select('.product-cr')
            if product_list:
                first_product = product_list[0]
                
                # Extract Detail Link
                link_tag = first_product.select_one('.name a')
                if not link_tag: return None
                detail_url = link_tag['href']
                
                # Fetch Detail Page
                res_detail = requests.get(detail_url, headers=headers, timeout=8)
                soup_detail = BeautifulSoup(res_detail.text, 'html.parser')
                
                title = soup_detail.select_one('h1.pr_header__heading').get_text(strip=True) if soup_detail.select_one('h1.pr_header__heading') else ""
                author = soup_detail.select_one('.pr_producers__manufacturer .pr_producers__link').get_text(strip=True) if soup_detail.select_one('.pr_producers__manufacturer .pr_producers__link') else ""
                publisher = soup_detail.select_one('.pr_producers__publisher .pr_producers__link').get_text(strip=True) if soup_detail.select_one('.pr_producers__publisher .pr_producers__link') else ""
                
                # Attributes map (Yayın Tarihi, Sayfa Sayısı etc.)
                attributes = {}
                for row in soup_detail.select('.attributes tr'):
                    cols = row.find_all('td')
                    if len(cols) == 2:
                        key = cols[0].get_text(strip=True)
                        val = cols[1].get_text(strip=True)
                        attributes[key] = val
                        
                pub_date = attributes.get('Yayın Tarihi', "")
                page_count = attributes.get('Sayfa Sayısı', 0)
                try: page_count = int(page_count)
                except: page_count = 0
                
                description = soup_detail.select_one('#description_text').get_text(strip=True) if soup_detail.select_one('#description_text') else ""
                
                # Image
                img_tag = soup_detail.select_one('#product-image')
                thumbnail = img_tag['src'] if img_tag else ""

                return {
                    "title": title,
                    "author": author,
                    "publisher": publisher,
                    "publication_year": pub_date[-4:] if len(pub_date) >= 4 else pub_date,
                    "page_count": page_count,
                    "description": description[:500] + "...", # Truncate long descriptions
                    "thumbnail_url": thumbnail,
                    "isbn": isbn
                }
    except Exception as e:
        print(f"Kitapyurdu Crawler Error: {e}")
    return None

def get_book_details(isbn, api_key=None):
    clean_isbn = clean_isbn_func(isbn)
    
    if not clean_isbn.isdigit() or len(clean_isbn) not in [10, 13]:
        print(f"Invalid ISBN: {isbn}")
        return None

    print(f"Searching for ISBN: {clean_isbn}")

    # 1. Try Orhan Aydogdu (Best for TR)
    print("Trying Orhan Aydogdu API...")
    res = fetch_orhan_aydogdu(clean_isbn)
    if res and res['title']: 
        print("Found in Orhan API!")
        return res

    # 2. Try Google Books (Global)
    print("Trying Google Books API...")
    res = fetch_google_books(clean_isbn)
    if res and res['title']:
        print("Found in Google Books API!")
        return res
        
    # 3. Try Library of Congress (NEW)
    print("Trying Library of Congress API...")
    res = fetch_loc(clean_isbn)
    if res and res['title']:
        print("Found in Library of Congress!")
        return res

    # 4. Try Open Library (Revised Endpoint)
    print("Trying Open Library API...")
    res = fetch_open_library(clean_isbn)
    if res and res['title']:
        print("Found in Open Library!")
        return res

    # 5. Try Kitapyurdu (Crawler - Last Resort)
    print("Trying Kitapyurdu Crawler...")
    res = fetch_kitapyurdu(clean_isbn)
    if res and res['title']:
        print("Found in Kitapyurdu!")
        return res

    print("Book not found in any source.")
    return None

if __name__ == "__main__":
    # Test
    print(get_book_details("9789750719387")) # Kürk Mantolu Madonna example
