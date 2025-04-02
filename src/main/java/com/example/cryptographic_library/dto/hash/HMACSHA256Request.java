package com.example.cryptographic_library.dto.hash;

/**
 * HMAC-SHA256请求参数传输对象
 *
 * <p>包含三个必需参数：
 * <ul>
 *   <li>key: 签名密钥（建议长度≥32字节）</li>
 *   <li>data: 待签名原始数据</li>
 *   <li>encoding: 签名结果编码方式</li>
 * </ul>
 */
public class HMACSHA256Request {
    private String key;
    private String data;
    private String encoding;

    public HMACSHA256Request(String key, String data, String encoding) {
        this.key = key;
        this.data = data;
        this.encoding = encoding;
    }

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
