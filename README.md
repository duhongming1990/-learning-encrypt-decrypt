# secure-util
## 简介

Base64编码，消息摘要，对称(DES,3DES,AES,IDEA)/非对称(RSA,ELGamal)加解密，消息验证码，RSA/DSA数字签名，数字证书/密钥库工具类

## 版本信息

V1.6 新增消息摘要：文件指纹

V1.5 前后台适用（Java、Nodejs、js）的对称/非对称加密与解密、消息摘要、消息验证码

V1.2 ~ V1.4 扩展工具类方法和修复bug

V1.1 增加数字证书工具类

V1.0 初始版本发布


## 注意
Java几乎各种常用加密算法都能找到对应的实现。因为美国的出口限制，Sun通过权限文件（local_policy.jar、US_export_policy.jar）做了相应限制。因此存在一些问题：

●密钥长度上不能满足需求（如：java.security.InvalidKeyException: Illegal key size or default parameters）；

●部分算法未能支持，如MD4、SHA-224等算法；

●API使用起来还不是很方便；一些常用的进制转换辅助工具未能提供，如Base64编码转换、十六进制编码转换等工具。

Oracle在其官方网站上提供了无政策限制权限文件（Unlimited Strength Jurisdiction Policy Files），我们只需要将其部署在JRE环境中，就可以解决限制问题。

Java 6 无政策限制文件：
http://www.oracle.com/technetwork/java/javase/downloads/jce-6-download-429243.html

Java 7 无政策限制文件：
http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html

## 参考

前台加密算法demo（DES、AES）：
https://github.com/brix/crypto-js

前台加密算法demo（RSA）：
https://github.com/travist/jsencrypt

后台加密算法demo（ALL）：
https://gitee.com/FlyTank/secure-util