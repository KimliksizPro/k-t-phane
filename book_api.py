import requests
import json

def get_book_details(isbn, api_key=None):
    """
    Fetches book details from Google Books API using an ISBN.

    Args:
        isbn (str): The ISBN-10 or ISBN-13 of the book.
        api_key (str, optional): Google Books API Key. Defaults to None.

    Returns:
        dict: A dictionary containing book details (title, authors, publisher, 
              publishedDate, pageCount, description, thumbnail) if found.
        None: If the book is not found or an error occurs.
    """
    # 1. Clean and Validate ISBN
    clean_isbn = str(isbn).replace("-", "").replace(" ", "").strip()
    
    if not clean_isbn.isdigit():
        print(f"Error: Invalid ISBN format: {isbn}")
        return None

    if len(clean_isbn) not in [10, 13]:
        print(f"Error: ISBN must be 10 or 13 digits. Got: {len(clean_isbn)}")
        return None

    # 2. Construct API URL
    base_url = "https://www.googleapis.com/books/v1/volumes"
    params = {
        "q": f"isbn:{clean_isbn}"
    }
    if api_key:
        params["key"] = api_key

    try:
        # 3. Make API Request
        response = requests.get(base_url, params=params)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

        data = response.json()

        # 4. Parse Response
        if "items" in data and len(data["items"]) > 0:
            volume_info = data["items"][0].get("volumeInfo", {})
            
            book_details = {
                "title": volume_info.get("title", "Unknown Title"),
                "authors": ", ".join(volume_info.get("authors", ["Unknown Author"])),
                "publisher": volume_info.get("publisher", "Unknown Publisher"),
                "published_date": volume_info.get("publishedDate", ""),
                "page_count": volume_info.get("pageCount", 0),
                "description": volume_info.get("description", ""),
                "categories": volume_info.get("categories", []),
                "thumbnail_url": volume_info.get("imageLinks", {}).get("thumbnail", "")
            }
            
            return book_details
        else:
            print(f"No book found for ISBN: {isbn}")
            return None

    except requests.exceptions.RequestException as e:
        print(f"API Request Error: {e}")
        return None
    except json.JSONDecodeError:
        print("Error decoding JSON response from API.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None

# Example Usage (for testing)
if __name__ == "__main__":
    # Test with a known ISBN (e.g., 'Clean Code' by Robert C. Martin)
    test_isbn = "9780132350884" 
    # You can pass your API key here if you have one, e.g., get_book_details(test_isbn, "YOUR_API_KEY")
    # Google Books API often works for public data without a key, but rate limits are lower.
    
    print(f"Fetching details for ISBN: {test_isbn}...")
    result = get_book_details(test_isbn)
    
    if result:
        print("\n--- Book Details Found ---")
        print(json.dumps(result, indent=4, ensure_ascii=False))
    else:
        print("\nFailed to fetch book details.")
