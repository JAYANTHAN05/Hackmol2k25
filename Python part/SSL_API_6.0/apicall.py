import requests
import urllib.parse
import re

def clean_url(url):
    """Clean and validate URL format"""
    # Remove any protocols
    cleaned = re.sub(r'^(http://|https://)', '', url)
    # Remove paths and query parameters
    cleaned = cleaned.split('/')[0]
    return cleaned.strip()

def check_ssl_certificate(url):
    api_url = "http://localhost:8000/api/ssl-check/"
    
    try:
        # Clean and prepare URL
        cleaned_url = clean_url(url)
        if not cleaned_url:
            return {"error": "Invalid URL format"}
            
        payload = {"url": cleaned_url}
        
        response = requests.post(api_url, json=payload)
        
        if response.status_code == 400:
            error_data = response.json()
            return {"error": error_data.get('error', 'Invalid request')}
            
        response.raise_for_status()
        return response.json()
        
    except requests.exceptions.ConnectionError:
        return {"error": "Cannot connect to API server. Is it running?"}
    except requests.exceptions.RequestException as e:
        return {"error": f"Request failed: {str(e)}"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}

def display_certificate_info(result):
    if "error" in result:
        print(f"\nError: {result['error']}")
        return
        
    print("\nSSL Certificate Information:")
    print("-" * 30)
    print(f"Status: {result.get('status', 'N/A')}")
    print(f"Hostname: {result.get('hostname', 'N/A')}")
    print(f"Issuer: {result.get('issuer', 'N/A')}")
    print(f"Expires on: {result.get('expires_on', 'N/A')}")
    print(f"Valid: {result.get('valid', False)}")

if __name__ == "__main__":
    print("\nSSL Certificate Checker")
    print("Enter a domain name to check its SSL certificate")
    print("Example: google.com")
    
    while True:
        website_url = input("\nEnter website URL to check SSL certificate (or 'quit' to exit): ")
        if website_url.lower() in ('quit', 'exit', 'q'):
            break
            
        result = check_ssl_certificate(website_url)
        display_certificate_info(result)