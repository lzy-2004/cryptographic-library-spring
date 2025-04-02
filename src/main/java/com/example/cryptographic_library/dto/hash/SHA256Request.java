package com.example.cryptographic_library.dto.hash;

/**
 * SHA-256请求参数传输对象
 *
 * <p>包含：
 * <ul>
 *   <li>data: 待哈希原始数据（非空）</li>
 *   <li>encoding: 输出编码格式标识</li>
 * </ul>
 */
public class SHA256Request {
    private String data;
    private String encoding;

    public SHA256Request(String data, String encoding) {
        this.data = data;
        this.encoding = encoding;
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
