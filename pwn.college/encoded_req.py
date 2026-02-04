import requests
import sys
from   urllib.parse import quote

TARGET = "http://challenge.localhost:80/"

def main():
    if len(sys.argv) < 3:
        print("Error")
        sys.exit(1)
    
    route = sys.argv[1] + "?"
    path = sys.argv[2]
    path = quote(path).replace("%3D","=")
    # path = path.replace("/", "%2f")
    query = TARGET + route + path
    print(f"query={query}")
    response = requests.get(query)
    print(response.text)

if __name__ == "__main__":
    main() 

"""
Make a req and encode it
"""