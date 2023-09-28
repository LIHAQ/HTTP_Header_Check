import argparse
import requests
import urllib3

# 发送HTTP请求头
def send_http_request(url, origin):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Origin': origin,
        'Accept-Encoding': 'gzip, deflate, br',
        'Referer': url,
        'Connection': 'keep-alive',
        'Cache-Control': 'no-cache',
        'Upgrade-Insecure-Requests': '1',
        'Pragma': 'no-cache',
    }
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    response = requests.get(url, headers=headers, verify=False)
    return response

# 检查缺少的请求头
def check_missing_headers(response):
    required_headers = [
        "X-Frame-Options",
        "X-Content-Type-Options",
        "X-XSS-Protection",
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "Referrer-Policy",
        "X-Download-Options",
        "X-Permitted-Cross-Domain-Policies",
    ]

    missing_headers = [
        header for header in required_headers if header not in response.headers
    ]

    return missing_headers

# 检查弱CORS漏洞
def check_cors_vulnerability(response, origin):
    cors_vulnerability = False

    if "Access-Control-Allow-Origin" in response.headers:
        allowed_origins = response.headers.get("Access-Control-Allow-Origin")
        if isinstance(allowed_origins, list):
            for allowed_origin in allowed_origins:
                if allowed_origin == "*" or allowed_origin == origin:
                    cors_vulnerability = True
                    break
                elif "," in allowed_origin:
                    allowed_origin_list = [item.strip() for item in allowed_origin.split(",")]
                    if "*" in allowed_origin_list or origin in allowed_origin_list:
                        cors_vulnerability = True
                        break
        elif allowed_origins == "*" or allowed_origins == origin:
            cors_vulnerability = True
        elif "," in allowed_origins:
            allowed_origin_list = [item.strip() for item in allowed_origins.split(",")]
            if "*" in allowed_origin_list or origin in allowed_origin_list:
                cors_vulnerability = True

    if not cors_vulnerability:
        # 如果"Access-Control-Allow-Origin"头不允许所有来源，可以继续检查其他CORS头
        if "Access-Control-Allow-Credentials" in response.headers:
            # 如果允许凭据（credentials），则可能存在弱CORS漏洞
            cors_vulnerability = True

        if "Access-Control-Allow-Headers" in response.headers:
            # 如果CORS允许自定义标头，也可能存在漏洞
            cors_vulnerability = True

        if "Access-Control-Allow-Methods" in response.headers:
            # 如果CORS允许自定义HTTP方法，也可能存在漏洞
            cors_vulnerability = True

    # 检查是否存在其他CORS标头
    other_cors_headers = [key for key in response.headers.keys() if key.startswith("Access-Control-")]
    if len(other_cors_headers) > 1:
        cors_vulnerability = True

    return cors_vulnerability




# 启用调试模式
def enable_debug_mode(response, debug):
  if debug:
    request_headers_str = ""  # 初始化请求头字符串
    response_headers_str = ""  # 初始化响应头字符串
    request_headers_str += "\n".join([f"{key}: {value}" for key, value in response.request.headers.items()])
    response_headers_str += "\n".join([f"{key}: {value}" for key, value in response.headers.items()])
    return request_headers_str, response_headers_str
  else:
        return "", ""  # 如果未启用调试模式，返回空字符串

# 生成结果字符串
def generate_result_string(request_headers, response_headers, missing_headers, cors_vulnerability, request_headers_str, response_headers_str):
    result = ""
    result += "-" * 45 + "\n"
    # 添加请求头信息
    if request_headers_str:
       
        result += "发送的请求头:\n"
        result += request_headers_str
        result += "\n"
        result += "-" * 45 + "\n"
    # 添加响应头信息
    if response_headers_str:
        
        result += "收到的响应头:\n"
        result += response_headers_str
        result += "\n"
        result += "-" * 45 + "\n"
    #请求头缺失信息
    if missing_headers:
        result += "以下HTTP头信息缺失：\n"
        for header in missing_headers:
            result += f"- {header}\n"
    else:
        result += "没有检测到HTTP头信息缺失\n"
    result += "-" * 45 + "\n"

    #CORS漏洞检测
    if cors_vulnerability:
        result += "存在CORS跨域漏洞\n"
    else:
        result += "未检测到CORS跨域漏洞\n"
    result += "-" * 45 + "\n"



    return result

# 保存结果到文件
def save_result_to_file(result, filename):
    with open(filename, "w", encoding="utf-8") as file:
        file.write(result)
    print(f"结果已导出到 {filename} 文件")

def main():
    parser = argparse.ArgumentParser(description="检测HTTP请求头缺失和CORS跨域漏洞")
    parser.add_argument("-u", "--url", required=True, help="目标URL")
    parser.add_argument("-o", "--origin", default="https://example.com", help="设置请求头中的Origin字段")
    parser.add_argument("-f", "--file", default=None, help="导出结果的文件名")
    parser.add_argument("-d", "--debug", action="store_true", help="启用调试模式")
    args = parser.parse_args()

    print("开始检测HTTP请求头缺失和CORS跨域漏洞...")
    print("目标URL:", args.url)
    print("Origin:", args.origin)

    response = send_http_request(args.url, args.origin)
    missing_headers = check_missing_headers(response)
    cors_vulnerability = check_cors_vulnerability(response, args.origin)
    request_headers_str, response_headers_str = enable_debug_mode(response, args.debug)

    result = generate_result_string(response.request.headers, response.headers, missing_headers, cors_vulnerability, request_headers_str, response_headers_str)
    
    print(result)

    if args.file is not None:
        if args.file.endswith(".txt"):
            save_result_to_file(result, args.file)
        else:
            print("请指定以 '.txt' 结尾的文件名进行导出。")

if __name__ == "__main__":
    main()
