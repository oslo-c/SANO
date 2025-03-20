from pystyle import Colors, Colorate, Center, Box
import requests
import os
from dotenv import load_dotenv, set_key
import phonenumbers
from phonenumbers import geocoder, carrier, timezone
import requests
from bs4 import BeautifulSoup
import urllib.parse
import json
import time
import hashlib
import datetime
import re
from requests.auth import HTTPBasicAuth
import binascii
import base64
from urllib.parse import urlparse, urljoin

os.system('cls')
load_dotenv()

def init_api_keys():
    """
    Check if the Hunter and Whois API keys are present in the .env file.
    If not, prompt the user to enter them and update the .env file.
    """
    hunter_key = os.getenv("HUNTER_KEY")
    whoisapi_key = os.getenv("WHOIS_KEY")
    updated = False

    if not hunter_key:
        hunter_key = input("Enter your Hunter API key: ").strip()
        set_key(".env", "HUNTER_KEY", hunter_key)
        updated = True

    if not whoisapi_key:
        whoisapi_key = input("Enter your Whois API key: ").strip()
        set_key(".env", "WHOIS_KEY", whoisapi_key)
        updated = True

    if updated:
        print("API keys have been updated and stored in your .env file.\n")

# Initialize API keys if missing
init_api_keys()

banner = r"""
     []                         ██████╗  █████╗ ██╗ ██████╗ 
            0        &         ██╔═══██╗██╔══██╗██║██╔═══██╗    0         $
                               ██║   ██║███████║██║██║   ██║                 ~~
       *                       ██║   ██║██╔══██║██║██║   ██║         ^         \
                  !            ╚██████╔╝██║  ██║██║╚██████╔╝   .         /\
             ~~                 ╚═════╝ ╚═╝  ╚═╝╚═╝ ╚═════╝ 
                                    github.com/scarlmao
"""

class key:
   hunter = os.getenv("HUNTER_KEY")
   whoisapi = os.getenv("WHOIS_KEY")

def bing_search(query):
    query = urllib.parse.quote(query)
    url = f"https://www.bing.com/search?q={query}"
    response = requests.get(url)
    
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        search_results = []
        for a in soup.find_all('a', href=True):
            href = a['href']
            if href.startswith('http') or href.startswith('www'):
                search_results.append(href)
        return search_results
    else:
        print(f"Error: {response.status_code}")
        return []

def print_box(title, content):
    print(Colors.purple + Box.DoubleCube(title))
    print(Colors.white + content)

def check_status(response, platform_name):
    if response.status_code == 200:
        return True
    return False

def default_check(response, platform_name):
    if response.status_code == 200:
        return True
    return False

def display_invite_info(res_json):
    invite_content = (
        f"Invite Link: https://discord.gg/{res_json.get('code', 'N/A')}\n"
        f"Channel: {res_json.get('channel', {}).get('name', 'N/A')} ({res_json.get('channel', {}).get('id', 'N/A')})\n"
        f"Expiration Date: {res_json.get('expires_at', 'N/A')}\n"
    )
    print_box("Invitation Information", invite_content)
  
    inviter_content = (
        f"Username: {res_json.get('inviter', {}).get('username', 'N/A')}#{res_json.get('inviter', {}).get('discriminator', 'N/A')}\n"
        f"User ID: {res_json.get('inviter', {}).get('id', 'N/A')}\n"
    )
    print_box("Inviter Information", inviter_content)
 
    server_content = (
        f"Name: {res_json.get('guild', {}).get('name', 'N/A')}\n"
        f"Server ID: {res_json.get('guild', {}).get('id', 'N/A')}\n"
        f"Banner: {res_json.get('guild', {}).get('banner', 'N/A')}\n"
        f"Description: {res_json.get('guild', {}).get('description', 'N/A')}\n"
        f"Custom Invite Link: {res_json.get('guild', {}).get('vanity_url_code', 'N/A')}\n"
        f"Verification Level: {res_json.get('guild', {}).get('verification_level', 'N/A')}\n"
        f"Splash: {res_json.get('guild', {}).get('splash', 'N/A')}\n"
        f"Features: {', '.join(res_json.get('guild', {}).get('features', []))}\n"
    )
    print_box("Server Information", server_content)

jsonOutput = {}
output = []
email_out = []

def findReposFromUsername(username):
    response = requests.get('https://api.github.com/users/%s/repos?per_page=100&sort=pushed' % username).text
    repos = re.findall(r'"full_name":"%s/(.*?)",.*?"fork":(.*?),' % username, response)
    nonForkedRepos = []
    for repo in repos:
        if repo[1] == 'false':
            nonForkedRepos.append(repo[0])
    return nonForkedRepos

def findEmailFromContributor(username, repo, contributor):
    response = requests.get('https://github.com/%s/%s/commits?author=%s' % (username, repo, contributor), auth=HTTPBasicAuth(username, '')).text
    latestCommit = re.search(r'href="/%s/%s/commit/(.*?)"' % (username, repo), response)
    if latestCommit:
        latestCommit = latestCommit.group(1)
    else:
        latestCommit = 'dummy'
    commitDetails = requests.get('https://github.com/%s/%s/commit/%s.patch' % (username, repo, latestCommit), auth=HTTPBasicAuth(username, '')).text
    email = re.search(r'<(.*)>', commitDetails)
    if email:
        email = email.group(1)
        email_out.append(email)
    return

def findEmailFromUsername(username):
    email_out = []  # Initialize a local list for email
    repos = findReposFromUsername(username)
    for repo in repos:
        findEmailFromContributor(username, repo, username)
    
    return email_out  # Return the list of emails found

def findPublicKeysFromUsername(username):
    gpg_response = requests.get(f'https://github.com/{username}.gpg').text
    ssh_response = requests.get(f'https://github.com/{username}.keys').text
    if not "hasn't uploaded any GPG keys" in gpg_response:
        output.append(f'[+] GPG_keys : https://github.com/{username}.gpg')
        jsonOutput['GPG_keys'] = f'https://github.com/{username}.gpg'
        regex_pgp = re.compile(r"-----BEGIN [^-]+-----([A-Za-z0-9+\/=\s]+)-----END [^-]+-----", re.MULTILINE)
        matches = regex_pgp.findall(gpg_response)
        if matches:
            b64 = base64.b64decode(matches[0])
            hx = binascii.hexlify(b64)
            keyid = hx.decode()[48:64]
            output.append(f'[+] GPG_key_id : {keyid}')
            jsonOutput['GPG_key_id'] = keyid
            emails = re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", b64.decode('Latin-1'))
            if emails:
                for email in emails:
                    email_out.append(email)
    if ssh_response:
        output.append(f'[+] SSH_keys : https:/github.com/{username}.keys')
        jsonOutput['SSH_keys'] = f'https://github.com/{username}.keys'

def findInfoFromUsername(username):
    url = f'https://api.github.com/users/{username}'
    response = requests.get(url)
    if response.status_code == 200 and requests.codes.ok:
        data = response.json()
        for i in data:
            if i in ['login','id','avatar_url','name','blog','location','twitter_username','email','company','bio','public_gists','public_repos','followers','following','created_at','updated_at']:
                if data[i] != None and data[i] != '':
                    if i == 'email':
                        email_out.append(data[i])
                    jsonOutput[i] = data[i]
                    output.append(f'[+] {i} : {data[i]}')
        jsonOutput['public_gists'] = f'https://gist.github.com/{username}'
        output.append(f'[+] public_gists : https://gist.github.com/{username}')
        return True
    elif response.status_code == 404:
        jsonOutput['error'] = 'username does not exist'
        return False
    
def extract_emails(content):
    email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    return re.findall(email_pattern, content)

def extract_links(content, base_url):
    soup = BeautifulSoup(content, 'html.parser')
    links = set()
    for a_tag in soup.find_all('a', href=True):
        link = a_tag['href']
        full_url = urljoin(base_url, link)
        links.add(full_url)
    return links

def extract_images(content, base_url):
    soup = BeautifulSoup(content, 'html.parser')
    images = set()
    for img_tag in soup.find_all('img', src=True):
        img_url = img_tag['src']
        full_url = urljoin(base_url, img_url)
        images.add(full_url)
    return images

def extract_subdomains(url):
    domain = urlparse(url).netloc
    subdomains = set()
    subdomain_pattern = r'([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,})'
    subdomains.add(domain)
    return subdomains

paths = [
    'admin', 'login', 'dashboard', 'index.php', 'config.php', 'public_html', 'uploads', '../../public_html', 'backup',
    'wp-admin', 'wp-content', 'wp-includes', 'wp-config.php', 'wp-login.php', 'wp-content/themes', 'wp-content/plugins',
    'wp-content/uploads', 'wp-content/cache', 'wp-content/languages', 'wp-content/upgrade', 'wp-content/backup-db',
    'cgi-bin', 'images', 'css', 'js', 'assets', 'media', 'includes', 'lib', 'modules', 'themes', 'plugins',
    'vendor', 'node_modules', 'composer.json', 'package.json', 'README.md', 'LICENSE', 'robots.txt', 'sitemap.xml',
    'error_log', 'logs', 'tmp', 'temp', 'cache', 'sessions', 'config', 'settings', 'database', 'db', 'sql',
    'backup.sql', 'dump.sql', 'data', 'files', 'docs', 'documentation', 'examples', 'tests', 'test', 'scripts',
    'bin', 'src', 'source', 'app', 'application', 'core', 'system', 'framework', 'public', 'private', 'protected',
    'resources', 'static', 'templates', 'views', 'controllers', 'models', 'migrations', 'seeds', 'factories',
    'storage', 'logs', 'env', '.env', '.htaccess', '.git', '.gitignore', '.svn', '.hg', '.bzr', '.idea', '.vscode',
    'private_key.pem', 'id_rsa', 'id_rsa.pub', 'ssh_config', 'authorized_keys', 'known_hosts', 'passwd', 'shadow',
    'group', 'hosts', 'hostname', 'network', 'resolv.conf', 'httpd.conf', 'nginx.conf', 'php.ini', 'my.cnf',
    'docker-compose.yml', 'Dockerfile', 'Makefile', 'Vagrantfile', 'Procfile', 'Jenkinsfile', 'build.gradle',
    'pom.xml', 'Gemfile', 'requirements.txt', 'Pipfile', 'yarn.lock', 'package-lock.json', 'bower.json', 'gulpfile.js',
    'Gruntfile.js', 'webpack.config.js', 'tsconfig.json', 'babel.config.js', 'eslint.json', 'prettier.config.js',
    'karma.conf.js', 'protractor.conf.js', 'jest.config.js', 'mocha.opts', 'travis.yml', 'circle.yml', 'appveyor.yml',
    'codecov.yml', 'coveralls.yml', 'sonar-project.properties', 'tox.ini', 'pytest.ini', 'setup.py', 'setup.cfg',
    'MANIFEST.in', 'pyproject.toml', 'Cargo.toml', 'Cargo.lock', 'build.rs', 'CMakeLists.txt', 'Makefile.am',
    'Makefile.in', 'configure.ac', 'configure.in', 'autogen.sh', 'bootstrap.sh', 'install.sh', 'uninstall.sh',
    'README', 'CHANGELOG', 'CONTRIBUTING', 'CODE_OF_CONDUCT', 'SECURITY', 'SUPPORT', 'ISSUE_TEMPLATE', 'PULL_REQUEST_TEMPLATE'
]

def main():
    os.system('cls')
    print(Center.XCenter((Colorate.Vertical(Colors.purple_to_blue, banner,1))))
    print(Colors.purple + Box.DoubleCube("[1] Google Dork            [7] Domain Lookup            [13] Site Crawler\n[2] Username Lookup        [8] Ip Lookup                [14] Site Path Finder\n[3] Email Lookup           [9] Discord Server Lookup\n\n[4] Phone Lookup           [10] Site Robots And Map\n[5] Court Lookup           [11] Github Lookup\n[6] Poeple Lookup          [12] Bin Lookup              [00] Exit"))

    i = input(Colors.white + "Input > ")

    if i == "14":
       base_url = input("Site > ")
       for path in paths:
        url = base_url + path
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                print(f'[+] Found: {url}')
            elif response.status_code == 403:
                print(f'[-] Access forbidden: {url}')
            else:
                print(f'[i] {response.status_code}: {url}')
        except requests.exceptions.Timeout:
            print(f'[!] Timeout for {url}')
        except requests.exceptions.RequestException as e:
            print(f'[!] Error while requesting {url}: {e}')
       input("Press Enter To Continue")
       main()

    if i == "00":
       os.system('exit')

    if i == "13":
       url = input("Site > ")
       try:
       
        response = requests.get(url)
        if response.status_code != 200:
            print(f"Error fetching the website: {response.status_code}")
            return

        content = response.text
        base_url = urlparse(url).scheme + "://" + urlparse(url).hostname

        emails = extract_emails(content)
        links = extract_links(content, base_url)
        images = extract_images(content, base_url)
        subdomains = extract_subdomains(url)

        print("\n[+] Emails found on the site:")
        for email in set(emails):
            print(email)

        print("\n[+] Links found on the site:")
        for link in set(links):
            print(link)

        print("\n[+] Images found on the site:")
        for image in set(images):
            print(image)

        print("\n[+] Subdomains found for the site:")
        for subdomain in set(subdomains):
            print(subdomain)

       except Exception as e:
        print(f"Error: {e}")
       input("Press Enter To Continue")
       main()

    if i == "12":
       bin1 = input("Input Bin > ")
       r = requests.get(f'https://lookup.binlist.net/{bin1}')
       print(r.text)
       
       input("Press Enter To Continue")
       main()


    if i == "11":
       gusername = input("Github User > ")
       repos = findReposFromUsername(gusername)
       try:
        email = findEmailFromUsername(gusername) 
        if not isinstance(email, list):  
            email = [email]
       except:
        email = ["None"] 
       info = findInfoFromUsername(gusername)

       if not isinstance(info, list):
         info = [str(info)] 

       print_box("Repos", "\n".join(repos))
       print_box("Emails", "\n".join(email))
       print_box("Other Info", "\n".join(info))

       input("Press Enter To Continue")
       main()



    if i == "10":
       site = input("Site > ")
       print(site + "/robots.txt")
       print(site + "/sitemap.xml")
       input("Press Enter To Continue")
       main()


    if i == "9":
     server = "discord.gg/lol"
     server = input("Discord Server Link > ")
     if "discord.gg" in server:
        code = server.split('/')[-1]
     else:
        code = server
    
 
     res = requests.get(f"https://discord.com/api/v9/invites/{code}")

     if res.status_code == 200:
        res_json = res.json()

        display_invite_info(res_json)

     else:
        print("Failed to retrieve invite data. Please check the server link and try again.")

     input("Press Enter To Continue")
     main()
        

    if i == "8":
       ip = input("Ip > ")
       response = requests.get(f"http://ip-api.com/json/{ip}")
       api = response.json()
       try:
        if api['status'] == "success": status = "Valid"
        else: status = "Invalid"
       except: 
        status = "Invalid"

       try:
           country_flag = api['country_flag']
       except:
           country_flag = "None"

       try:
           country = api['country']
       except:
           country = "None"

       try:
           country_code = api['countryCode']
       except:
           country_code = "None"

       try:
           region = api['regionName']
       except:
           region = "None"

       try:
           region_code = api['region']
       except:
           region_code = "None"

       try:
           zip_code = api['zip']
       except:
           zip_code = "None"

       try:
           city = api['city']
       except:
           city = "None"

       try:
           latitude = api['lat']
       except:
           latitude = "None"

       try:
           longitude = api['lon']
       except:
           longitude = "None"

       try:
           timezone = api['timezone']
       except:
           timezone = "None"

       try:
           isp = api['isp']
       except:
           isp = "None"

       try:
           org = api['org']
       except:
           org = "None"

       try:
           as_host = api['as']
       except:
           as_host = "None"
       info = [
        f"Status: {status}",
        f"Country Flag: {country_flag}",
        f"Country: {country}",
        f"Country Code: {country_code}",
        f"Region: {region}",
        f"Region Code: {region_code}",
        f"ZIP Code: {zip_code}",
        f"City: {city}",
        f"Latitude: {latitude}",
        f"Longitude: {longitude}",
        f"Timezone: {timezone}",
        f"ISP: {isp}",
        f"Organization: {org}",
        f"AS Host: {as_host}"
    ]

       print_box("Info About Ips", "\n".join(info))
       input("Press Enter To Continue")
       main()
       

    if i == "7":
       site = input("Site > ")
       r = requests.get(f'https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={key.whoisapi}&domainName={site}&outputFormat=JSON').text
       print(r)
       input("Press Enter To Continue")
       main()

    if i == "1":
        dork = input("Input Google Dork To Search > ")
        results = bing_search(dork)
        print_box("Google Dork", "\n".join([f"{key}: {value}" for key, value in phone_data.items()]))
        if results:
         for idx, url in enumerate(results, 1):
          print(f"{idx}. {url}")
          dorks = []
          dorks.append(idx,url)
         else:
          print("")
         print_box("Dorking", "\n".join([f"{key}: {value}" for key, value in dorks.items()]))
         input("Press Enter To Continue")
         main()

    if i == "2":
       username = input("Username > ")
       platforms = [
    "https://github.com/",
    "https://community.signalusers.org/u/",
    "https://www.snapchat.com/add/",
    "https://open.spotify.com/user/",
    "https://cash.me/",
    "https://www.last.fm/user/",
    "https://en.gravatar.com/",
    "https://pastebin.com/u/",
    "https://www.buymeacoffee.com/",
    "https://www.chess.com/member/",
    "https://www.gamespot.com/profile/",
    "https://gitlab.com/",
    "https://www.roblox.com/user.aspx?username=",
    "https://scratch.mit.edu/users/",
    "https://soundcloud.com/",
    "https://api.mojang.com/users/profiles/minecraft/",
    "https://osu.ppy.sh/users/",
    "https://replit.com/@",
    "https://genius.com/artists/",
    "https://www.speedrun.com/users/",
    "https://picsart.com/u/",
    "https://lichess.org/@/",
    "https://youtube.com/@",
]

       found = []
       retries = 5
       backoff_factor = 1.5
       timeout = 120
       attempt = 1
       for platform in platforms:
        try:
         
         headers = {
            "user-agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0"
         }
         url = f"{platform}{username}"
         response = requests.get(url, headers=headers, timeout=5) 
         if response.status_code == 200:
          found.append(f"{url}")
        except requests.exceptions.ConnectTimeout:
         print(f"Attempt {attempt + 1} failed. Retrying in {timeout} seconds...")
         time.sleep(timeout)
         timeout *= backoff_factor 

       print_box("Social Media Accounts", "\n".join(found))
       input("Press Enter To Continue")
       main()
       
             


    if i == "3":
      mail = input("Email > ")
      stealerlogs = "None"
      status = "None"
      github = "None"
      chess = "None"
      pinterest = "None"
      spotify = "None"
      twitter = "None"
      firefox = "None"
      Gravatar = "None"
      linkedin = "None"
      snapchat = "None"
      imgur = "None"
      mailscore = "None"
      proton = "None"
      adobe = "None"
      rubmaps = "None"
      wordpress = "None"
      first_seen = "None"
      bandlab = "None"
      deezer = "None"
      picsart = "None"
      strava = "None"
      xvideos = "None"
      anydo = "None"
      flickr = "None"
      freelancer = "None"
      coroflot = "None"
      voxmedia = "None"
      replit = "None"
      pastes = "None"
      pastebin = "None"
      devrant = "None"
      vrbo = "None"

      stealerlogs = []
      response = requests.get(f'https://api.hunter.io/v2/email-verifier?email={mail}&api_key={key.hunter}')
      result = response.json()["data"]["result"]
      if "deliverable" in result:
       status = "Working"
      response = requests.get(f'https://leakcheck.net/api/public?key=49535f49545f5245414c4c595f4150495f4b4559&check={mail}')
 
      if "error" not in response.text:
       sources = response.json()["sources"]
       for source in sources:
        name = source["name"]
        date = source["date"]
        stealerlogs.append(name+date)
      response = requests.get(f"https://api.github.com/search/users?q={mail}+in:email")
      if response.status_code == 200:
       data = response.json()
       if data["total_count"] == 0 or not data["items"]:
            pass
            github = "None"
       else:
        guser = data["items"][0]["login"]
        github = f"Found | {guser}"
      response = requests.post(f"https://www.chess.com/callback/email/available?email={mail}")
      if response.json()['isEmailAvailable'] == False:
       reason = response.json()['reason']
       chess = f"Found | {reason}"

      params={
        "source_url": "/",
        "data": '{"options": {"email": "'+ mail +'"}, "context": {}}'
    }
      r = requests.get("https://www.pinterest.fr/resource/EmailExistsResource/get/", params=params)
      if r.json()["resource_response"]["data"]:
       code = r.json()["resource_response"]["http_status"]
       pinterest = f"Found | {code}"

      r = requests.get(f"https://spclient.wg.spotify.com/signup/public/v1/account?validate=1&email={mail}")
      if r.json()['status'] == 20:
       spotify = "Found | 200"

       r = requests.get(f"https://api.twitter.com/i/users/email_available.json?email={mail}")
       if r.json()['taken']:
        twitter = "Found | 200"

    

    email_hash=hashlib.md5(mail.encode('utf-8')).hexdigest()
    response=requests.get("https://www.gravatar.com/" + email_hash)
    if response.status_code==200:
     response = requests.get(response.url + '.json')
     username = response.json()["entry"][0]["preferredUsername"]
     display = response.json()["entry"][0]["displayName"]
     Gravatar = f"Found | Display = {display} | User = {username}"
    
    response = requests.get("https://www.linkedin.com/sales/gmail/profile/viewByEmail/" + mail)
    if response.status_code == 200:
     linkedin = "Found | 200"
   
    URL = "https://bitmoji.api.snapchat.com/api/user/find"

    data = {
        'email': mail
    }

    r = requests.get(URL, data=data)

    if '{"account_type":"snapchat"}' in r.text:
            snapchat = "Found | 200"

    else:
          pass
    
    response = requests.get(f'https://api.hunter.io/v2/email-verifier?email={mail}&api_key={key.hunter}')
    mailscore = response.json()["data"]["score"]

    URL = "https://imgur.com/signin/ajax_email_available"

    data = {
        'email': mail
    }
 
    r = requests.get(URL,data=data)

    if """{"data":{"available":false},"success":true,"status":200""" in r.text:
            imgur = "Found | 200"

    URL = "https://api.protonmail.ch/pks/lookup?op=index&search={}"
    r = requests.get(URL.format(mail))
    if "info:1:0" in r.text:
            pass
    elif "info:1:1" in r.text:
            pat1 = "2048:(.*)::"
            pat2 = "22::(.*)::"
            pat3 = "4096:(.*)::"

            regex_pat = [pat1, pat2, pat3]

            for regex in regex_pat:
                timestamp = re.search(regex, r.text)
                if timestamp:
                    dtimeobject = datetime.fromtimestamp(
                        int(timestamp.group(1)))
                    proton = f"Found | Created = {dtimeobject} UTC"
                else:
                    continue

    else:
            pass

    headers = {
        'content-type': 'application/json',
        'x-ims-clientid': 'adobedotcom2',
    }

    json_data = {
        'username': mail,
    }

    response = requests.post(
        'https://auth.services.adobe.com/signin/v2/users/accounts',
        headers=headers,
        json=json_data,
    )
    adobe = '"None"'

    if adobe in response.text:
        adobe = "Found | 200"

    headers = {
        'content-type': 'application/x-www-form-urlencoded',
    }

    data = {
        'email': mail,
        'ajax': '1',
    }

    response = requests.post('https://www.rubmaps.ch/signup', headers=headers, data=data)

    if "1" in response.text:
        rubmaps = "Found | 200"
    
    params = {
        'http_envelope': '1',
    }
    response = requests.get(
        'https://public-api.wordpress.com/rest/v1.1/users/{}/auth-options'.format(mail),
        params=params,
    )
    if "200" in response.text:
        wordpress = "Found | 200"

    r = requests.get(f'https://ipqualityscore.com/api/json/email/lPnx5AhAUv4jgIFDXquYpe8CVBjmaTii/{mail}')
    iso = r.json()["first_seen"]["iso"]
    first_seen = iso

    r = requests.get(f"https://www.bandlab.com/api/v1.3/validation/user", params={'email': mail})
    response_json = response.json()
    is_valid = response_json.get('isValid', None)  
    if is_valid is not None and is_valid:
        is_available = response_json.get('isAvailable', None)
        if is_available is False:
            bandlab = "Found | 200"

    p = requests.Session()

    r = p.post("https://www.deezer.com/ajax/gw-light.php?method=deezer.getUserData&input=3&api_version=1.0&api_token=&cid=")
    token = r.json()['results']['checkForm']

    params = {
            'method': 'deezer.emailCheck',
            'input': 3,
            'api_version': 1.0,
            'api_token': token,
        }

    api = p.post(f"https://www.deezer.com/ajax/gw-light.php", params=params, data='{"EMAIL":"'+ mail +'"}')
    if api.json()['results']['availability'] == True:
            pass

    elif api.json()['results']['availability'] == False:
            deezer = "Found | 200"
    p.close()

    params = {
        'email_encoded': 1,
        'emails': mail
    }

    r = requests.get("https://api.picsart.com/users/email/existence", params=params)

    if r.json()['status'] == 'success':
        
        if r.json()['response']:
            picsart = "Found | 200"

    params = {'email': mail}

    req = requests.get(f"https://www.strava.com/frontend/athletes/email_unique", params=params)

    if "false" in req.text:
            strava = "Found | 200"

    headers = {
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'X-Requested-With': 'XMLHttpRequest',
        'Connection': 'keep-alive',
        'Referer': 'https://www.xvideos.com/',
    }

    params = {
        'email': mail,
    }
    response = requests.get('https://www.xvideos.com/account/checkemail', headers=headers, params=params)
    if "This email is already in use or its owner has excluded it from our website" in response.text:
       xvideos = "Found | 200"

    headers = {
        'Accept': '*/*',
        'Accept-Language': 'en,en-US;q=0.5',
        'Referer': 'https://desktop.any.do/',
        'Content-Type': 'application/json; charset=UTF-8',
        'X-Platform': '3',
        'Origin': 'https://desktop.any.do',
        'DNT': '1',
        'Connection': 'keep-alive',
        'TE': 'Trailers',
    }

    data = '{"email":"' + mail + '"}'

    response = requests.post('https://sm-prod2.any.do/check_email', headers=headers, data=data)
    if response.status_code == 200:
     if response.json()["user_exists"]:
        anydo = "Found | 200"

    url = "https://identity-api.flickr.com/migration"
    headers = {
        'Accept': '*/*',
        'Accept-Language': 'es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3',
        'Referer': 'https://identity.flickr.com/login',
        'Origin': 'https://identity.flickr.com',
        'Connection': 'keep-alive',
        'TE': 'Trailers',
    }

    response = requests.get(url + "?email=" + str(mail), headers=headers)
    data = json.loads(response.text)
    if 'state_code' in str(data.keys()) and data['state_code'] == '5':
     flickr = "Found | 200"

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0',
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3',
        'Content-Type': 'application/json',
        'Origin': 'https://www.freelancer.com',
        'DNT': '1',
        'Connection': 'keep-alive',
        'TE': 'Trailers',
    }

    data = '{"user":{"email":"' + mail + '"}}'

    response = requests.post('https://www.freelancer.com/api/users/0.1/users/check?compact=true&new_errors=true', data=data, headers=headers)
    resData = response.json()
    if response.status_code == 409 and "EMAIL_ALREADY_IN_USE" in response.text:
     freelancer = "Found | 200"

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0',
        'Accept': '*/*',
        'Accept-Language': 'en,en-US;q=0.5',
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-Requested-With': 'XMLHttpRequest',
        'Origin': 'https://www.coroflot.com',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Referer': 'https://www.coroflot.com/signup',
        'TE': 'Trailers',
    }

    data = {
        'email': mail
    }

    response = requests.post('https://www.coroflot.com/home/signup_email_check',headers=headers,data=data)
    if response.json()["data"] == -2:
     coroflot = "Found | 200"


    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0',
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Accept-Language': 'en,en-US;q=0.5',
        'Referer': 'https://auth.voxmedia.com/login',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'X-Requested-With': 'XMLHttpRequest',
        'Origin': 'https://auth.voxmedia.com',
        'DNT': '1',
        'Connection': 'keep-alive',
        'TE': 'Trailers',
    }

    data = {
        'email': mail
    }

    response = requests.post('https://auth.voxmedia.com/chorus_auth/email_valid.json', headers=headers, data=data)

    if "That email address belongs to a registered user." in response.json()["message"]:
     voxmedia = "Found | 200"

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0',

        'Accept': 'application/json',
        'Accept-Language': 'fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3',
        'content-type': 'application/json',
        'x-requested-with': 'XMLHttpRequest',
        'Origin': 'https://replit.com',
        'Connection': 'keep-alive',
    }

    data = '{"email":"' + str(mail) + '"}'

    response = requests.post('https://replit.com/data/user/exists', headers=headers, data=data)
    if response.json()['exists']:
     replit = "Found | 200"

    
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0',
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'X-Requested-With': 'XMLHttpRequest',
        'Origin': 'https://devrant.com',
        'Connection': 'keep-alive',
        'Referer': 'https://devrant.com/feed/top/month?login=1',
    }

    data = {
        'app': '3',
        'type': '1',
        'email': mail,
        'username': '5555',
        'password': '55555Aa',
        'guid': '',
        'plat': '3',
        'sid': '',
        'seid': ''
    }

    response = requests.post('https://devrant.com/api/users', headers=headers, data=data)
    error = response.json()['error']
    if error == 'The email specified is already registered to an account.':
     devrant = "Found | 200"


    headers = {
'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0',
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.5',
        'Content-Type': 'application/json',
        'x-homeaway-site': 'vrbo',
        'Origin': 'https://www.vrbo.com',
        'DNT': '1',
        'Connection': 'keep-alive',
        'TE': 'Trailers',
    }

    data = '{"emailAddress":"' + mail + '"}'
    
    response = requests.post(
            'https://www.vrbo.com/auth/aam/v3/status',
            headers=headers,
            data=data)
    response = response.json()
    if "authType" in response.keys():
     if response["authType"][0] == "LOGIN_UMS":
          vrbo = "Found | 200"


    



    data = {
    "Social Media Accounts": {
        "Github": github,
        "Chess": chess,
        "Pinterest": pinterest,
        "Twitter": twitter,
        "Firefox": firefox,
        "Gravatar": Gravatar,
        "Linkedin": linkedin,
        "Snapchat": snapchat
    },
    "Entertainment & Media Services": {
        "Spotify": spotify,
        "Bandlab": bandlab,
        "Deezer": deezer,
        "Picsart": picsart,
        "Xvideos": xvideos,
        "Coroflot": coroflot
    },
    "Productivity & Utilities": {
        "Mail Score": mailscore,
        "Adobe": adobe,
        "Rubmaps": rubmaps,
        "Anydo": anydo,
        "Freelancer": freelancer,
        "Replit": replit
    },
    "User Info & History": {
        "Stealer Logs": stealerlogs,
        "Status": status,
        "First Seen": first_seen
    },
    "File & Data Related": {
        "Pastes": pastes,
        "Pastebin": pastebin,
        "Devrant": devrant
    },
    "Miscellaneous": {
        "Strava": strava,
        "Vrbo": vrbo,
        "Voxmedia": voxmedia
    }
}

    response = requests.get(f'https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={mail}')
    jsondata = response.json()
    if "stealers" in jsondata and isinstance(jsondata["stealers"], list) and len(jsondata["stealers"]) > 0:
     stealer_info = jsondata["stealers"][0]
     data["Stealer Information"] = {
        "IP": stealer_info.get("ip"),
        "Passwords": stealer_info.get("top_passwords"),
        "Logins": stealer_info.get("top_logins"),
        "Computer Name": stealer_info.get("computer_name"),
        "Antiviruses": stealer_info.get("antiviruses"),
        "Date of Breach": stealer_info.get("date_compromised")
    }

    if "stealers" in jsondata and isinstance(jsondata["stealers"], list) and len(jsondata["stealers"]) > 0:
        stealer_info = jsondata["stealers"][0]
        data["Stealer Information"] = {
            "IP": stealer_info.get("ip"),
            "Passwords": stealer_info.get("top_passwords"),
            "Logins": stealer_info.get("top_logins"),
            "Computer Name": stealer_info.get("computer_name"),
            "Antiviruses": stealer_info.get("antiviruses"),
            "Date of Breach": stealer_info.get("date_compromised")
        }


    json_output = json.dumps(data, indent=4)
    print_box("Social Media Accounts", "\n".join([f"{key}: {value}" for key, value in data["Social Media Accounts"].items()]))
    print_box("Entertainment & Media Services", "\n".join([f"{key}: {value}" for key, value in data["Entertainment & Media Services"].items()]))
    print_box("Productivity & Utilities", "\n".join([f"{key}: {value}" for key, value in data["Productivity & Utilities"].items()]))
    print_box("Stealer Logs", "\n".join([f"{key}: {value}" for key, value in data["User Info & History"].items()]))
    print_box("Pastes", "\n".join([f"{key}: {value}" for key, value in data["File & Data Related"].items()]))
    print_box("Misc", "\n".join([f"{key}: {value}" for key, value in data["Miscellaneous"].items()]))
    print_box("Logs", "\n".join([f"{key}: {value}" for key, value in data["Stealer Information"].items()]))

    input("Press Enter To Continue")
    main()

    with open('email_lookup_output.txt', 'w') as f:
     f.write(json_output)


    

    if i == "4":
        print("Phone Number ( Make Sure To Have Proper Format No Spaces at the Start)")
        phone_numberr = input("Input > ")
        phone_number = "+1" + phone_numberr
        parsed_number = phonenumbers.parse(phone_number)
        
        country = geocoder.region_code_for_number(parsed_number)
        location = geocoder.description_for_number(parsed_number, "en")
        
        phone_carrier = carrier.name_for_number(parsed_number, "en")
        
        timezones = timezone.time_zones_for_number(parsed_number)
        
        is_valid = phonenumbers.is_valid_number(parsed_number)
        
        is_possible = phonenumbers.is_possible_number(parsed_number)
        
        phone_data = {
            "Phone Number": phone_number,
            "Valid": is_valid,
            "Possible": is_possible,
            "Location": location,
            "Country Code": country,
            "Carrier": phone_carrier if phone_carrier else "N/A",
            "Timezones": ", ".join(timezones) if timezones else "N/A"
        }
        results = bing_search(phone_numberr)
        print_box("Phone Data", "\n".join([f"{key}: {value}" for key, value in phone_data.items()]))
        if results:
         for idx, url in enumerate(results, 1):
          print(f"{idx}. {url}")
          dorks = []
          dorks.append(idx,url)
         else:
          print("")
         print_box("Dorking", "\n".join([f"{key}: {value}" for key, value in dorks.items()]))


       





    if i == "5":
      print("Type Case Information: ")
      casen = input("Input > ")
      url = f'https://www.courtlistener.com/api/rest/v4/search/?q={casen}'
      headers = {
    'Authorization': 'Token 3b62c99a62731722e96f029b807bd8f9557dcbe2'  
}

      response = requests.get(url, headers=headers)


      if response.status_code == 200:
       data = response.json()

       cases_info = []
    
       for case in data['results']:
         case_info = {
            
            'caseName': case.get('caseName', 'N/A'),
            'court': case.get('court', 'N/A'),
            'dateFiled': case.get('dateFiled', 'N/A'),
            'docketNumber': case.get('docketNumber', 'N/A'),
            'judge': case.get('judge', 'N/A'),
            'status': case.get('status', 'N/A'),
            'absolute_url': case.get('absolute_url', 'N/A'),
            'opinion_url': case['opinions'][0].get('download_url', 'N/A') if case.get('opinions') else 'N/A',
            'snippet': case['opinions'][0].get('snippet', 'N/A') if case.get('opinions') else 'N/A'
            
        }
         case_info_str = "\n".join([f"{key}: {value}" for key, value in case_info.items()])
         cases_info.append("\n\n" + case_info_str)



       print(Colors.white + str(cases_info))
       input("Press Enter To Continue")
       main()



    if i == "6":
        first_name = input("First Name > ")
        last_name = input("First Name > ")
        state = input("State > ")
        city = input("City > ")



        cookies = {

    'cf_clearance': 'hPk.ajKbUrJgW_6UD6v0p6Wx2Do6_OpdyMKEqpGTtGc-1740287990-1.2.1.1-cjY7Tj8GPRGsf3dAssi.AVMu6qaMCLLgAPssCNDpqYFxM0DxcPDj2_EvEJOEIDWOiRP84HSe7m6iYTqmV_SKJ6YQJ5lWWxC5ZZaDxLxMvYt8C8CAW9VfKUenm64GwxzFphKezM57k.rqnkw1nRrmMwYie00RBVAf2j0Ayhy58sWRrjMVXmylOi.mf1z9JsRmgFPYU1nbkUbOyhmnHUrFK3Jl9sWmYPdgueWDWfN5wWigUarqqsUzscPEhZL5cC718aRIXcAlZbAGBqjsFQp_cbMkNwa_MZ3Xv0dB7fHhNSRCWqOo6f_h0sX6WKc8ODEzc5tk20GtifcmQuCoBIqIyA',

}

        headers = {
    'accept': '*/*',
    'content-type': 'application/json',
    'origin': 'https://www.searchpeoplefree.com',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0',
    'x-requested-with': 'XMLHttpRequest',
}

        json_data = {
    'page': 'Name_Results',
    'last': f'{last_name}',
    'first': f'{first_name}',
    'phone': '',
    'email': '',
    'unit': '',
    'house': '',
    'street': '',
    'line1': '',
    'city': f'{city}',
    'state': f'{state}',
}

        response = requests.post('https://www.searchpeoplefree.com/api/v3/getslots', cookies=cookies, headers=headers, json=json_data)
        json_response = response.json()
        for slot in json_response.get("listSlots", []):
         for item in slot.get("items", []):
          full_name = item.get("n", "No Name")
          addresses = item.get("ads", [])
        
          print(f"Name: {full_name}")
          print("Addresses:")
          for address in addresses:
            city = address.get("City", "No City")
            state = address.get("State", "No State")
            zip_code = address.get("Zip", "No Zip")
            print(f" - {city}, {state} {zip_code}")
          print("-" * 30)
          results = bing_search(first_name + ' ' + last_name)
          print(phone_data)
          if results:
           for idx, url in enumerate(results, 1):
            print(f"{idx}. {url}")
           else:
            print("")
          input("Press Enter To Continue")
          main()

main()
