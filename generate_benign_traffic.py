import time
import random
import requests
import socket
import logging
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

# Configuration
TOP_SITES = [
    "https://www.google.com", "https://www.youtube.com", "https://www.facebook.com",
    "https://www.amazon.com", "https://www.wikipedia.org", "https://twitter.com",
    "https://www.instagram.com", "https://www.linkedin.com", "https://www.reddit.com",
    "https://www.netflix.com", "https://www.microsoft.com", "https://www.apple.com"
]

BENIGN_DOMAINS = [
    "weather.com", "cnn.com", "bbc.co.uk", "github.com", "stackoverflow.com",
    "medium.com", "dropbox.com", "paypal.com", "adobe.com", "whatsapp.com"
]

def setup_driver():
    """Configures headless Chrome driver."""
    chrome_options = Options()
    chrome_options.add_argument("--headless") 
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    # Suppress logging
    chrome_options.add_argument("--log-level=3")
    
    # Initialize driver (Ensure 'chromedriver' is in PATH)
    try:
        driver = webdriver.Chrome(options=chrome_options)
        return driver
    except Exception as e:
        print(f"[WARN] Selenium not available: {e}")
        print("       Falling back to requests-only mode.")
        return None

def browse_websites(driver):
    """Simulates real browsing behavior."""
    if driver:
        try:
            target = random.choice(TOP_SITES)
            print(f"[BROWSE] Visiting: {target}")
            driver.get(target)
            time.sleep(random.uniform(2, 5)) # Stay on page
        except Exception:
            pass
    else:
        # Fallback to requests
        try:
            target = random.choice(TOP_SITES)
            print(f"[HTTP] Getting: {target}")
            requests.get(target, timeout=2)
        except Exception:
            pass

def perform_dns_lookup():
    """Performs standard DNS A-record lookups."""
    try:
        domain = random.choice(BENIGN_DOMAINS)
        print(f"[DNS] Looking up: {domain}")
        socket.gethostbyname(domain)
    except Exception:
        pass

def main():
    print("=== BENIGN TRAFFIC GENERATOR ===")
    print("Simulating realistic user behavior (Browsing + DNS)...")
    
    driver = setup_driver()
    
    try:
        count = 0
        while True:
            # 1. Random Web Browsing
            if random.random() > 0.3:
                browse_websites(driver)
            
            # 2. Random DNS Lookups
            if random.random() > 0.5:
                perform_dns_lookup()
                
            # Random sleep between actions (Human behavior)
            sleep_time = random.uniform(0.5, 3.0)
            time.sleep(sleep_time)
            
            count += 1
            if count % 10 == 0:
                print(f"--- Generated {count} actions ---")
                
    except KeyboardInterrupt:
        print("\n[STOP] Traffic generation stopped.")
    finally:
        if driver:
            driver.quit()

if __name__ == "__main__":
    main()
