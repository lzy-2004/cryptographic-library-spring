package com.example.cryptographic_library.dto.hash;

public class SHA1Request {
    private String data;
    private String encoding; // hex 或 base64

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
