package com.example.cryptographic_library.dto.symmetric;

/**
 * RC6请求参数传输对象
 *
 * <p>包含：
 * <ul>
 *   <li>key: 加密/解密密钥（4-32字节）</li>
 *   <li>data: 待处理数据（加密时为明文，解密时为密文）</li>
 *   <li>outputEncoding: 编码格式标识</li>
 * </ul>
 */
public class RC6Request {
    private String key;
    private String data;
    private String outputEncoding; // 密文输出编码（base64/hex）

    public RC6Request(String key, String data, String outputEncoding) {
        this.key = key;
        this.data = data;
        this.outputEncoding = outputEncoding;
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

    public String getOutputEncoding() {
        return outputEncoding;
    }

    public void setOutputEncoding(String outputEncoding) {
        this.outputEncoding = outputEncoding;
    }
}
