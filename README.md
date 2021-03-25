# OtterDNS

OtterDNS 一个权威DNS解析软件

#### 1. 支持特性

- 基于Rust实现的权威解析软件
- 提供DNS数据报文的二进制序列化及反序列操作
- 提供对于标准Zone文件的读取和加载(不支持Bind扩展指令)
- 提供基于红黑树的数据存储模型的定义和操作



#### 附录. 实现RFC

- [RFC 1034](https://tools.ietf.org/html/rfc1034) 域名服务器查询响应及数据存储
- [RFC 1035](https://tools.ietf.org/html/rfc1035) 基本的DNS协议，字段，区文件数据解析
- [RFC 4343](https://tools.ietf.org/html/rfc4343) DNS字符标签格式声明
