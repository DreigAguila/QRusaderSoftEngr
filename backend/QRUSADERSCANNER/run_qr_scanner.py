#!/usr/bin/env python3
import os
import sys
import subprocess
import webbrowser
import threading
import time

def open_browser(url):
    """Open the browser after a short delay to let the server start."""
    time.sleep(2)  # wait 2s so Flask has time to boot
    print(f"🌐 Opening {url} in your browser...")
    webbrowser.open(url)

def main():
    print("QRusader - QR Code Scanner Launcher\n" + "="*50)
    
    while True:
        print("1. 🎥 Start Camera QR Scanner")
        print("2. 🌐 Start Web Interface (Flask)")
        print("3. ❌ Exit")
        choice = input("Enter choice (1-3): ").strip()

        if choice == "1":
            print("Starting camera scanner...")
            subprocess.run([sys.executable, "backend/QRUSADERSCANNER/qr_scanner_testing.py"])
            break

        elif choice == "2":
            print("Starting Flask web interface...")

            url = "http://127.0.0.1:5000"

            # Start browser in background
            threading.Thread(target=open_browser, args=(url,), daemon=True).start()

            # Run Flask server (blocking call)
            subprocess.run([sys.executable, "backend/QRUSADERSCANNER/app.py"])
            break

        elif choice == "3":
            print("Goodbye!")
            break

        else:
            print("Invalid choice, try again.\n")

if __name__ == "__main__":
    main()
