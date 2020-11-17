# ukiwi
自研威胁分析框架
# 基于静态规则的流量分析

- 例1

http_req : method == GET ; uri 包含 `%252F` ,两次 url 解码后包含` ../`

http_resp: status == 200 ; body 包含 `root:x:0:0:root:/root:/bin/`

```yaml
info:
  description: Spring Cloud Config Server 路径穿越与任意文件读取漏洞 cve-2019-3799
  protocol: http
match:
  http_req:
    method: "GET" 
    uri:
      content_1: "%252F"
      decode: ['url','url']
      content_2: "../"
  http_resp:
    status: 200
    body: 
      content: "root:x:0:0:root:/root:/bin/"
```

- 例2

http_req: method == GET ; url 包含 `/web/index.php?` 和 `.git` ; header 的 authorization 字段包含 `Basic` 并且经过 base 解码后包含 `<?php`

```yaml
info:
  description: GitStack 文件上传漏洞 CVE-2018-5955
  protocol: http
match:
  http_req:
    method: "GET" 
    uri:
      content_1: "/web/index.php?"
      content_2: ".git"
    headers:
      authorization:
        content_1: "Basic"
        decode: ['base']
        content_2: "<?php"
```



# 规则字段

- info

| description |                   描述文字                   |
| :---------: | :------------------------------------------: |
|  protocol   | 首选协议，http:匹配 http,tcp; tcp 仅匹配 tcp |

- match

  - http_req

  | method  |                请求方式                 |
  | :-----: | :-------------------------------------: |
  |   uri   |            content,decode,re            |
  | headers | content,decode,re; headers 字段均可匹配 |
  |  body   |            content,decode,re            |

  

  - http_resp
  | status | response 状态码, 数字 |
| :----: | :-------------------: |
|  body  |   content,decode,re   |

