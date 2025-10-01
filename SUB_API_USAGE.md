# Sub API 使用说明

## 概述

Sub API 是 SUBMIX 项目中新增的一个 API 端点，用于将多个代理节点链接融合到一个 Mihomo (Clash Meta) 配置文件中。

## API 地址

```
/api/sub
```

## 请求格式

### GET 请求

```
https://${subconverter}/sub?target=mihomo&url=${encodeURIComponent(request.url)}&insert=false&config=${encodeURIComponent(subconfig)}
```

### POST 请求

```json
{
  "target": "mihomo",
  "url": "https://example.com/subscription1|https://example.com/subscription2",
  "insert": false,
  "config": "{\"ruleMode\":\"whitelist\",\"configType\":\"simple\"}"
}
```

## 参数说明

| 参数 | 类型 | 必需 | 说明 |
|------|------|------|------|
| `target` | string | 是 | 目标类型，目前仅支持 `mihomo` |
| `url` | string | 是 | 节点链接，多个节点用 `|` 分割，需要 URL 编码。支持 VLESS、Hysteria、Hysteria2、Shadowsocks、Trojan 等协议 |
| `insert` | boolean | 否 | 是否插入额外配置（暂未实现） |
| `config` | string | 否 | 配置参数，JSON 格式，需要 URL 编码 |

## 配置参数 (config)

config 参数支持以下选项：

```json
{
  "ruleMode": "whitelist",     // 规则模式: "whitelist" (白名单) 或 "blacklist" (黑名单)
  "configType": "simple"      // 配置类型: "simple" (简化版) 或 "full" (完整版)
}
```

## 使用示例

### 示例 1: 单个节点

```bash
curl "http://localhost:3000/api/sub?target=mihomo&url=vless%3A%2F%2Fuuid%40example.com%3A443%3Fsecurity%3Dtls%26type%3Dws%26host%3Dexample.com"
```

### 示例 2: 多个节点

```bash
curl "http://localhost:3000/api/sub?target=mihomo&url=vless%3A%2F%2Fuuid%40example.com%3A443%7Ctrojan%3A%2F%2Fpassword%40example2.com%3A443%7Css%3A%2F%2FYWVzLTI1Ni1nY206cGFzc3dvcmQ%40example3.com%3A443"
```

### 示例 3: 带配置参数

```bash
curl "http://localhost:3000/api/sub?target=mihomo&url=vless%3A%2F%2Fuuid%40example.com%3A443&config=%7B%22ruleMode%22%3A%22blacklist%22%2C%22configType%22%3A%22full%22%7D"
```

### 示例 4: POST 请求

```bash
curl -X POST "http://localhost:3000/api/sub" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "mihomo",
    "url": "vless://uuid@example.com:443?security=tls&type=ws|trojan://password@example2.com:443",
    "config": {
      "ruleMode": "whitelist",
      "configType": "simple"
    }
  }'
```

### 示例 5: 不同协议的节点

```bash
curl "http://localhost:3000/api/sub?target=mihomo&url=vless%3A%2F%2Fuuid1%40example.com%3A443%7Chysteria2%3A%2F%2Fexample.com%3A443%3Fauth%3Dpassword%7Ctrojan%3A%2F%2Fpassword%40example2.com%3A443%7Css%3A%2F%2FYWVzLTI1Ni1nY206cGFzc3dvcmQ%40example3.com%3A443"
```

## 响应格式

### 成功响应

返回 YAML 格式的 Mihomo 配置文件，Content-Type 为 `text/yaml`。

响应头包含：
- `X-Proxy-Count`: 解析到的代理节点数量
- `X-Node-Count`: 输入的节点链接数量

### 错误响应

返回 JSON 格式的错误信息：

```json
{
  "error": "错误描述",
  "details": "详细错误信息（仅在开发环境下显示）"
}
```

## 功能特性

1. **多节点支持**: 支持同时处理多个节点链接，用 `|` 分割
2. **协议支持**: 支持 VLESS、Hysteria、Hysteria2、Shadowsocks、Trojan 等主流协议
3. **配置灵活**: 支持白名单/黑名单模式，简化版/完整版配置
4. **节点融合**: 将多个节点链接融合到一个 YAML 配置文件中
5. **错误处理**: 完善的错误处理和日志记录

## 注意事项

1. 节点链接必须经过 URL 编码
2. 多个节点链接用 `|` 分割（注意不是本项目常用的换行分割）
3. 配置参数如果包含特殊字符，也需要进行 URL 编码
4. API 会自动过滤无效的节点链接和空行
5. 支持的协议包括：VLESS、Hysteria、Hysteria2、Shadowsocks、Trojan 等
