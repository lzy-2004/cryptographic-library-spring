package com.example.cryptographic_library.dto.hash;

/**
 * SHA-1请求参数传输对象
 *
 * <p>包含：
 * <ul>
 *   <li>data: 待哈希原始数据（非空）</li>
 *   <li>encoding: 输出编码格式标识</li>
 * </ul>
 */
public class SHA1Request {
    private String data;
    private String encoding; // hex 或 base64

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
