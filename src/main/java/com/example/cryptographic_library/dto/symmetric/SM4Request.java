package com.example.cryptographic_library.dto.symmetric;

public class SM4Request {
    private String key;
    private String data;
    private String encoding; // "hex" 或 "base64"

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

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
