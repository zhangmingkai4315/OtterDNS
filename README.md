# OtterDNS

OtterDNS 一个权威DNS解析软件

#### 1. 支持特性

- 基于Rust实现的权威解析软件
- 提供DNS数据报文的二进制序列化及反序列操作
- 提供对于标准Zone文件的读取和加载(不支持Bind扩展指令)
- 提供基于红黑树的数据存储模型的定义和操作

#### 2. 查询逻辑
1. 实现单个节点下的域名遍历（iterator和标签的Ord的配合使用）
2. 实现搜索的逻辑实现
    - 假设节点为根节点, 查询域名为www.google.com
    - 现在当前节点查询com节点，如果当前子节点中存在com则递归查询com节点的子节点中google节点，如果依然命中则在google节点的子节点中查询www 
    - 如果任何查询流程中查询不到，则判断是否支持统配，如果支持的话则检查"*"的标记节点，并统配后续的所有子标签。
    - 如果支持统配，但是不存在"*"则返回当前节点 。如果不支持且未找到，则返回当前节点
    - 查询过程中任何的节点如果存在NS记录顺便返回回来，作为标记ZoneCut的节点。
3.  实现一个基于Tokio的UDP服务器

#### 附录. 实现RFC

- [RFC 1034](https://tools.ietf.org/html/rfc1034) 域名服务器查询响应及数据存储
- [RFC 1035](https://tools.ietf.org/html/rfc1035) 基本的DNS协议，字段，区文件数据解析
- [RFC 4343](https://tools.ietf.org/html/rfc4343) DNS字符标签格式声明
- [RFC 4034](https://tools.ietf.org/html/rfc4343) DNSSEC记录定义
- [RFC 2782](https://tools.ietf.org/html/rfc2782) SRV记录定义
- [RFC 1876](https://tools.ietf.org/html/rfc1876) LOC记录定义
- [RFC 5155](https://tools.ietf.org/html/rfc5155) DNSSEC NSEC3
