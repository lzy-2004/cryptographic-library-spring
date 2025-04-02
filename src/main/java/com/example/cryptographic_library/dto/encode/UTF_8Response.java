package com.example.cryptographic_library.dto.encode;

/**
 * UTF-8响应参数传输对象
 *
 * <p>标准化接口响应格式，包含：
 * <ul>
 *   <li>status: 操作状态码（0=成功，-1=通用错误，-2=格式错误）</li>
 *   <li>message: 操作结果描述</li>
 *   <li>result: 处理结果数据（失败时为null）</li>
 * </ul>
 */
public class UTF_8Response {
    private int status;
    private String message;
    private String result;

    public UTF_8Response(int status, String message, String result) {
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
