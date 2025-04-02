package com.example.cryptographic_library.dto.asymmetric;

public class RSA1024Request {

    private String data;
    private String key;
    private String modulus;
    private String encoding;

    /**
     * RSA算法请求参数载体
     * @param data 处理数据（明文/密文）
     * @param key 密钥（公钥/私钥）
     * @param modulus 模数n
     * @param encoding 数据编码方式（base64/hex）
     */
    public RSA1024Request(String data, String key, String modulus, String encoding) {
        this.data = data;
        this.key = key;
        this.modulus = modulus;
        this.encoding = encoding;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }

    public String getKey() {
        return this.key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public String getModulus() {
        return modulus;
    }

    public void setModulus(String modulus) {
        this.modulus = modulus;
    }

    public String getEncoding() {
        return encoding;
    }

    public void setEncoding(String encoding) {
        this.encoding = encoding;
    }
}
