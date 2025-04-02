package com.example.cryptographic_library.dto.hash;

/**
 * RIPEMD-160请求参数传输对象
 *
 * <p>包含：
 * <ul>
 *   <li>data: 待哈希原始数据（非空）</li>
 *   <li>outputEncoding: 输出编码格式标识</li>
 * </ul>
 */
public class RIPEMD160Request {
    private String data;
    private String outputEncoding;

    public RIPEMD160Request(String data, String outputEncoding) {
        this.data = data;
        this.outputEncoding = outputEncoding;
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
