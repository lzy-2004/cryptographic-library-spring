package com.example.cryptographic_library.dto.encode;

public class UTF_8Request {
    private String data;

    private String encoding;

    public UTF_8Request(String data, String encoding) {
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
