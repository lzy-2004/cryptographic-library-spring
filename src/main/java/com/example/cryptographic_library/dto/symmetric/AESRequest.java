package com.example.cryptographic_library.dto.symmetric;

/**
 * AES请求参数传输对象
 *
 * <p>包含：
 * <ul>
 *   <li>key: 加密/解密密钥（16/24/32字节）</li>
 *   <li>data: 待处理数据（明文或密文）</li>
 *   <li>outputEncoding: 编码格式标识</li>
 * </ul>
 */
public class AESRequest {
    private String key;
    private String data;
    private String outputEncoding;

    public AESRequest(String key, String data, String outputEncoding) {
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
