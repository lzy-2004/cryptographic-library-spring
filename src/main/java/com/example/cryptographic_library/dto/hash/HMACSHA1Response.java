package com.example.cryptographic_library.dto.hash;

/**
 * HMAC-SHA1响应参数传输对象
 *
 * <p>标准化响应格式包含：
 * <ul>
 *   <li>status: 操作状态码（0=成功，-1=失败）</li>
 *   <li>message: 操作结果描述</li>
 *   <li>result: 签名结果字符串</li>
 * </ul>
 */
public class HMACSHA1Response {
    private int status;
    private String message;
    private String result;

    public HMACSHA1Response(int status, String message, String result) {
        this.status = status;
        this.message = message;
        this.result = result;
    }

    public int getStatus() {
        return status;
    }

    public void setStatus(int status) {
        this.status = status;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getResult() {
        return result;
    }

    public void setResult(String result) {
        this.result = result;
    }
}
