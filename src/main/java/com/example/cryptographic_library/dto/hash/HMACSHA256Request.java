package com.example.cryptographic_library.dto.hash;

public class HMACSHA256Request {
    private String key;
    private String data;
    private String encoding;

    public HMACSHA256Request(String key, String data, String encoding) {
        this.key = key;
        this.data = data;
        this.encoding = encoding;
    }

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
