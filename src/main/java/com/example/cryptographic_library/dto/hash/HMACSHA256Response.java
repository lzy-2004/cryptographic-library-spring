package com.example.cryptographic_library.dto.hash;

/**
 * HMAC-SHA256响应参数传输对象
 *
 * <p>包含：
 * <ul>
 *   <li>status: 状态码（0=成功，-1=失败）</li>
 *   <li>message: 操作结果描述</li>
 *   <li>result: 64字符hex字符串或44字符base64字符串</li>
 * </ul>
 */
public class HMACSHA256Response {
    private int status;
    private String message;
    private String result;

    public HMACSHA256Response(int status, String message, String result) {
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
