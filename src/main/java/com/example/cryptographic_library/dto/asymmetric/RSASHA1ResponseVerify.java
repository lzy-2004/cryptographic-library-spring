package com.example.cryptographic_library.dto.asymmetric;

public class RSASHA1ResponseVerify {
    private int status;
    private String message;
    private Boolean result;

    public RSASHA1ResponseVerify(int status, String message, Boolean result) {
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

    public Boolean getResult() {
        return result;
    }

    public void setResult(Boolean result) {
        this.result = result;
    }
}
