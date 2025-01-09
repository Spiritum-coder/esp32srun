# ESP-IDF srun
基于ESP-IDF的网络转接工具，并支持认证深澜校园网。

- 基于ESP-IDF的softap_sta示例项目修改，支持连接wifi、开启ap并开启nat转接
- 自动认证深澜校园网
- 定时ping检测网络并重新认证

使用esp32c3在地大（CUG）未来城校园网测试成功。

加密思路来自[https://zhuanlan.zhihu.com/p/122556315](https://zhuanlan.zhihu.com/p/122556315)

hmac_md5加密代码来自[https://blog.csdn.net/a823837282/article/details/107931442](https://blog.csdn.net/a823837282/article/details/107931442)


## 使用说明
使用`idf.py menuconfig`配置ap ssid以及password。

修改`main/login.c`中所有192.168.167.115为认证网页的ip地址。

修改`main/softap_sta.c`中所有的username为校园网账号，password为深澜校园网。

