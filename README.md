# HTTP请求头检测工具

这是一个用于检测HTTP请求头缺失和CORS跨域漏洞的工具。

## 功能特点

- 检测给定URL的HTTP请求头是否缺失必需的字段。
- 检测给定URL是否存在CORS跨域漏洞。
- 将结果导出到文件中。

## 安装依赖

在运行脚本之前，请确保已安装以下依赖项：

- Python 3.x
- requests>=2.26.0
- urllib3>=1.26.7

你可以使用以下命令安装依赖项：

```shell
pip install -r requirements.txt
````
使用方法
在命令行中运行以下命令来检测HTTP请求头缺失和CORS跨域漏洞：

````shell
python HTTP_Header_Check.py -u <URL> -o <Origin> -f <filename>
````

参数说明：
- -u 或 --url：目标URL。
- -o 或 --origin：设置请求头中的Origin字段（可选，默认为 https://example.com）。
- -f 或 --file：导出结果的文件名（可选）。

## 示例
以下示例演示如何使用该工具进行检测：

````shell
python HTTP_Header_Check.py -u https://www.baidu.com -o https://example.com -f result.txt
````
![image](https://github.com/LIHAQI/HTTP_Header_Check/assets/57976650/7dcfd00a-b443-4286-b29f-242c8936f220)



## 注意事项
请确保你有合适的权限和许可来对目标URL进行测试。
使用该工具时要遵守适用的法律法规和道德准则。

## 贡献
欢迎提出问题、建议和改进意见！请使用 GitHub 的 Issues
