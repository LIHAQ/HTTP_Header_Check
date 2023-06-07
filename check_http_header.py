import requests
import urllib3
import argparse

http_head = [
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "X-Download-Options",
    "X-Permitted-Cross-Domain-Policies"
]

user_agent = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
    "Accept-Encoding": "gzip, deflate",
    "Connection":"close",
}

user_agent1 = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
    "Accept-Encoding": "gzip, deflate",
    "Connection":"close",
    "Origin":"https://test.com"
}

get_http_headlist = []

def get_url(url):
    try:
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
        url_html = requests.get(url=url, headers=user_agent, verify=False)
        url_html2 = requests.get(url=url, headers=user_agent1, verify=False)
    except requests.exceptions.SSLError as e:
        print("SSL证书验证失败：%s" % str(e))
        return []
    if url_html2.headers.get("Access-Control-Allow-Origin"):
        if "https://test.com" in url_html2.headers.get("Access-Control-Allow-Origin"):
            print("%s 存在CORS跨域漏洞"%url)
        else:
            print("%s 不存在CORS跨域漏洞"%url)
    for key in url_html.headers.keys():
        get_http_headlist.append(key)
    return get_http_headlist

def check_http_head(list_http_headers):
    for i in http_head:
        if i not in list_http_headers:
            print("HTTP %s 缺失"%i)

def patch_ssl_ciphers():
    try:
        urllib3.util.ssl_.DEFAULT_CIPHERS += 'HIGH:!DH:!aNULL'
    except AttributeError:
        pass  # no problem, fallback to the older version urllib3

def main():
    patch_ssl_ciphers()
    parse = argparse.ArgumentParser()
    parse.description = 'input target url'
    parse.add_argument("-u","--input u",help="target url",dest="url",type=str,default=None)
    args = parse.parse_args()
    list_http_headers = get_url(args.url)
    check_http_head(list_http_headers)

if __name__ == "__main__":
    main()