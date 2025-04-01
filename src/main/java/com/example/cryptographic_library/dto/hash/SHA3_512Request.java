package com.example.cryptographic_library.dto.hash;

public class SHA3_512Request {
    private String data;
    private String encoding;

    public SHA3_512Request(String data, String encoding) {
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
