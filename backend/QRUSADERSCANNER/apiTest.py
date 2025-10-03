import requests

API_KEY = "AIzaSyBFFrYMX2p6DYJ-7gkxblCO4R6GkCSWg7Y"  # replace with env in prod
url = "http://testsafebrowsing.appspot.com/s/malware.html"

body = {
    "client": {"clientId": "your-app", "clientVersion": "1.0"},
    "threatInfo": {
        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
        "platformTypes": ["ANY_PLATFORM"],
        "threatEntryTypes": ["URL"],
        "threatEntries": [{"url": url}],
    },
}

resp = requests.post(
    f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}",
    json=body,
)

print(resp.status_code)
print(resp.json())
