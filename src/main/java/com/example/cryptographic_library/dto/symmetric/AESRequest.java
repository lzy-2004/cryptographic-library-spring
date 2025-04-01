package com.example.cryptographic_library.dto.symmetric;

public class AESRequest {
    private String key;
    private String data;
    private String outputEncoding;

    public AESRequest(String key, String data, String outputEncoding) {
        this.key = key;
        this.data = data;
        this.outputEncoding = outputEncoding;
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

    public String getOutputEncoding() {
        return outputEncoding;
    }

    public void setOutputEncoding(String outputEncoding) {
        this.outputEncoding = outputEncoding;
    }
}
