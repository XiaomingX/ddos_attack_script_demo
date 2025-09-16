# DDoS攻击脚本 - 多层级攻击与安全验证工具

<p align="center"><strong>重要提示：</strong>本工具仅限于授权范围内用于安全测试，请勿在未获授权情况下实施攻击行为，避免违法风险。</p>

---

## 项目简介

本脚本为多线程多协议DDoS攻击模拟工具，支持Layer 4（传输层）和Layer 7（应用层）多种攻击方式，可用于验证防护产品（如WAF、防火墙、DDoS防护系统）的抗压能力及漏洞检测。

---

## 主要功能 & 攻击方式

### 应用层攻击（Layer 7）

- HTTP GET / POST Flood泛洪攻击
- HTTP POST带大数据量请求
- 绕过验证码的请求模拟
- 随机HEX编码请求
- 异常User-Agent模拟攻击（绕过WAF）
- 非标准HTTP方法攻击（PUT、OPTIONS、HEAD等）
- 慢速POST变种（Slowloris改进）
- 参数污染攻击（制造大量无害参数扰乱检测）
- 正则表达式拒绝服务（ReDoS）模拟
- API接口登录爆破模拟

### 传输层攻击（Layer 4）

- TCP、UDP Flood泛洪攻击
- SYN、ACK、RST Flood攻击
- ICMP洪水攻击
- NTP、DNS放大攻击（反射攻击）
- SSDP、多协议放大攻击

---

## 依赖与安装

### 环境要求

- Python 3.x
- 依赖库（可选，视使用功能）：  
  - `dnspython`  
  - `requests`

### 安装命令

```
pip install -r requirements.txt
```

### 运行脚本

```
python3 src/main.py
```

---

## 使用说明

- 修改 `src/main.py` 中 `target`（目标IP及端口）、`method`（攻击名称）、`threads`（线程数）和`duration`（攻击时长）参数以符合测试需求。
- 支持的方法名称示例：  
  `tcp`, `udp`, `syn`, `ack`, `rst`, `icmp`, `ntp`, `dns`, `ssdp`, `http_get`, `http_post`, `slowloris`, `redos`, `api_flood`, `abnormal_ua`, `nonstandard_http_methods`, `payload_obfuscation`, `header_injection`, `slowpost_variant`, `param_pollution`等。

---

## 警告及免责声明

- 本项目仅用于安全测试、教育及研究目的，禁止非法使用。
- 使用本工具前请务必获得网络或系统所有者的明确授权。
- 作者和本仓库不对任何违法行为负责。

---

## 贡献指南

欢迎提交Issue反馈问题或功能建议，欢迎Fork并发起Pull Request改进代码。

---

## 许可证

本项目遵循 MIT License 许可证授权。

---

## 联系方式

如需帮助或合作，请联系项目维护人员。

---

> 本README根据2025年GitHub最佳实践标准编写，提升搜索引擎友好度与项目文档体验。
