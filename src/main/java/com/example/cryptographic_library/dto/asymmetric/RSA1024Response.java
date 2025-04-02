package com.example.cryptographic_library.dto.asymmetric;

public class RSA1024Response {

    private int status;
    private String message;
    private String result;

    /**
     * RSA算法标准响应格式
     * @param status 操作状态码：
     *               0 - 操作成功
     *              -1 - 操作失败
     * @param message 结果描述信息
     * @param result 处理结果数据（根据操作类型返回不同内容）
     */
    public RSA1024Response(int status, String message, String result) {
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
