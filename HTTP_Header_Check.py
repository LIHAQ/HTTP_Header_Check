import argparse
import requests
import urllib3


def check_missing_headers(url):
    # 发送HTTP GET请求
    response = requests.get(url, verify=False)

    # 检查是否存在缺失的请求头
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

    # 输出结果
    result = ""
    if missing_headers:
        result += "以下HTTP头信息缺失：\n"
        for i, header in enumerate(missing_headers):
            result += f"- {header}"
            if i < len(missing_headers) - 1:
                result += "\n"
    else:
        result += "没有检测到HTTP头信息缺失"

    print(result)
    return result


def check_cors_vulnerability(url, origin):
    # 发送跨域请求
    headers = {"Origin": origin}
    response = requests.get(url, headers=headers, verify=False)

    # 检查响应头是否包含 Access-Control-Allow-Origin
    if "Access-Control-Allow-Origin" in response.headers:
        allowed_origin = response.headers["Access-Control-Allow-Origin"]
        if allowed_origin == "*" or allowed_origin == origin:
            return True

    return False


def save_result_to_file(result, filename):
    with open(filename, "w") as file:
        file.write(result)
    print(f"结果已导出到 {filename} 文件")


def main():
    # 解析命令行参数
    parser = argparse.ArgumentParser(description="检测HTTP请求头缺失和CORS跨域漏洞")
    parser.add_argument("-u", "--url", required=True, help="目标URL")
    parser.add_argument(
        "-o", "--origin", default="https://example.com", help="设置请求头中的Origin字段"
    )
    parser.add_argument("-f", "--file", default=None, help="导出结果的文件名")
    args = parser.parse_args()

    # 调用函数进行检测
    print("开始检测HTTP请求头缺失和CORS跨域漏洞...")
    print("目标URL:", args.url)
    print("Origin:", args.origin)
    print("---------------------------------------------")

    result = check_missing_headers(args.url)
    print("---------------------------------------------")
    has_cors_vulnerability = check_cors_vulnerability(args.url, args.origin)
    if has_cors_vulnerability:
        print(f"{args.url} 存在CORS跨域漏洞！")
    else:
        print(f"{args.url} 不存在CORS跨域漏洞。")
    print("---------------------------------------------")

    if args.file is not None:
        if args.file.endswith(".txt"):
            save_result_to_file(result, args.file)
        else:
            print("请指定以 '.txt' 结尾的文件名进行导出。")


if __name__ == "__main__":
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()
