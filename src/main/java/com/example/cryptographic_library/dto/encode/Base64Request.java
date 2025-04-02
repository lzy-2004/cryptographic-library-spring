package com.example.cryptographic_library.dto.encode;

/**
 * Base64请求参数传输对象
 *
 * <p>用于接收前端传递的编解码参数</p>
 */
public class Base64Request {
    /** 待处理的数据（编码时为原始字符串，解码时为Base64字符串） */
    private String data;

    public Base64Request(String data) {
        this.data = data;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }
}
