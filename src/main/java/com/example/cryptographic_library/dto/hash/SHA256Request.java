package com.example.cryptographic_library.dto.hash;

public class SHA256Request {
    private String data;
    private String encoding;

    public SHA256Request(String data, String encoding) {
        this.data = data;
        this.encoding = encoding;
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
