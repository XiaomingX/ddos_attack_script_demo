# DDoS攻击脚本

<p align="center">仅用于授权情况下验证安全产品的抗DDoS能力，请不要在未经网站所有者同意的情况下进行攻击。</p>

## 功能和攻击方式

**Layer 7 (应用层攻击)：**
- GET 和 POST 请求泛洪、绕过 OVH、随机 HEX、绕过验证码、发送大字节数据的请求等。

**Layer 4 (传输层攻击)：**
- TCP/UDP 泛洪、SYN 泛洪、ICMP 请求、DNS 放大攻击等。

**工具支持：**
- 查找 Cloudflare 网站真实 IP、DNS 解析、Ping 服务器等。

### 快速开始

**需求：**
- Python3 以及一些必要的依赖库，如 `dnspython`、`requests` 等。

**安装脚本：**
```
  python3 main.py
```

**一键安装：**
```shell
待更新
```

## 注意事项

请不要使用 "Issues" 部分提问。
