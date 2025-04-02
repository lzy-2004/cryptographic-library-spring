package com.example.cryptographic_library.dto.hash;

/**
 * SHA-256响应参数传输对象
 *
 * <p>状态码说明：
 * <ul>
 *   <li>0: 成功（32字节哈希值）</li>
 *   <li>-1: 参数错误</li>
 *   <li>-2: 服务端内部错误</li>
 * </ul>
 */
public class SHA256Response {
    private int status;
    private String message;
    private String result;

    public SHA256Response(int status, String message, String result) {
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
