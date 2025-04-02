package com.example.cryptographic_library.dto.symmetric;

/**
 * SM4请求参数传输对象
 *
 * <p>包含：
 * <ul>
 *   <li>key: 128位加密/解密密钥</li>
 *   <li>data: 待处理数据（加密时为明文，解密时为密文）</li>
 *   <li>encoding: 编码格式标识</li>
 * </ul>
 */
public class SM4Request {
    private String key;
    private String data;
    private String encoding; // "hex" 或 "base64"

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }

    public String getEncoding() {
        return encoding;
    }

    public void setEncoding(String encoding) {
        this.encoding = encoding;
    }
}
