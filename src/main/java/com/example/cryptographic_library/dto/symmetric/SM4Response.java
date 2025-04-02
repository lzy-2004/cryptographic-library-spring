package com.example.cryptographic_library.dto.symmetric;

/**
 * SM4响应参数传输对象
 *
 * <p>状态码说明：
 * <ul>
 *   <li>0: 操作成功</li>
 *   <li>-1: 输入参数错误</li>
 *   <li>-2: 加解密过程错误</li>
 * </ul>
 */
public class SM4Response {
    private int status;
    private String message;
    private String result;
    public SM4Response(int status, String message, String result) {
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
