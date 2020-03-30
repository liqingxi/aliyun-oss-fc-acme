## aliyun-oss-fc-acme

利用函数计算自动为OSS更新证书

特性

* 基于tiny-acme申请ssl证书
* 自动在OSS上创建验证文件
* 自动推送证书到aliyun CDN
* 能够在函数计算的环境运行

## 使用方法

修改`config.example.py`并保存为`config.py`

打包zip

```
zip code.zip *.py
```

上传到阿里云函数计算

测试时的运行配置：

| 参数         | 值           |
| ------------ | ------------ |
| 函数入口     | main.handler |
| 运行环境     | python3      |
| 函数执行内存 | 128M         |
| 超时时间     | 60           |

设置为定时任务，自动续期

## acme-tiny

https://github.com/diafygi/acme-tiny