import requests

# Trigger scan
scan_response = requests.post(
    'http://localhost:8000/api/xss/scan/',
    json={ "url": "https://xss-game.appspot.com/level1/frame" }
)
print("Scan Trigger Response:", scan_response.json())

# Get logs
logs_response = requests.get('http://localhost:8000/api/xss/logs/')
print("Scan Logs:", logs_response.json())
