# Cryptographic Library

基于Java的密码学算法实现库，提供对称加密、非对称加密、哈希算法等核心功能，遵循主流密码学标准。

![Java](https://img.shields.io/badge/Java-17%2B-blue)
![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.0.6-brightgreen)
![License](https://img.shields.io/badge/License-MIT-green)

## 功能特性

### 加密算法支持
| 类型          | 算法               | 标准/模式               |
|---------------|--------------------|------------------------|
| 对称加密      | AES-128/192/256    | ECB/PKCS7Padding       |
|               | RC6                | ECB/PKCS7Padding       |
|               | SM4                | 国密标准               |
| 非对称加密    | RSA-1024           | PKCS#1 v1.5           |
|               | ECC-160            | secp160r1             |
| 哈希算法      | SHA-1/SHA-256      | FIPS 180-4            |
|               | SHA3-512           | FIPS 202              |
|               | RIPEMD-160         | ISO/IEC 10118-3:2004  |
| HMAC          | HMAC-SHA1/256      | RFC 2104              |
| 密钥派生      | PBKDF2             | RFC 2898              |

## 快速开始

### 环境要求
- JDK 17+
- Maven/Gradle

### 构建项目  
```bash 
git clone https://github.com/lzy-2004/cryptographic-library-spring.git 
cd cryptographic-library 
./gradlew build  
``` 

## API 使用示例
### AES 加密
```bash
curl -X POST http://localhost:8080/api/aes/encrypt -H "Content-Type: application/json" -d '{ "key": "2b7e151628aed2a6abf7158809cf4f3c", "data": "Hello World", "outputEncoding": "base64" }'
```
### RSA 密钥生成
```bash
curl -X GET http://localhost:8080/api/rsa1024/generate-keypair
```

## 项目结构
src/  
├── main  
│ ├── java/com/example/cryptographic_library  
│ │ ├── algorithm # 算法核心实现  
│ │ │ ├── asymmetric # 非对称加密算法  
│ │ │ ├── symmetric # 对称加密算法  
│ │ │ └── hash # 哈希算法  
│ │ │ └── encode # 编码算法  
│ │ ├── controller # REST API 入口  
│ │ ├── service # 业务逻辑层  
│ │ └── dto # 数据传输对象  
└── test # 单元测试  
