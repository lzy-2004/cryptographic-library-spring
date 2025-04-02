package com.example.cryptographic_library.dto.hash;

/**
 * SHA-1响应参数传输对象
 *
 * <p>状态码说明：
 * <ul>
 *   <li>0: 成功（20字节哈希值）</li>
 *   <li>-1: 处理失败</li>
 * </ul>
 */
public class SHA1Response {
    private int status;
    private String message;
    private String result;

    public SHA1Response(int status, String message, String result) {
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
