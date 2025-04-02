package com.example.cryptographic_library.dto.encode;

/**
 * UTF-8请求参数传输对象
 *
 * <p>包含两个必需参数：
 * <ul>
 *   <li>data: 待处理数据（编码时为字符串，解码时为指定格式字符串）</li>
 *   <li>encoding: 数据格式标识（hex/binary/octal/decimal）</li>
 * </ul>
 */
public class UTF_8Request {
    private String data;

    private String encoding;

    public UTF_8Request(String data, String encoding) {
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
