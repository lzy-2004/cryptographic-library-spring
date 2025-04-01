package com.example.cryptographic_library.dto.hash;

public class RIPEMD160Request {
    private String data;
    private String outputEncoding;

    public RIPEMD160Request(String data, String outputEncoding) {
        this.data = data;
        this.outputEncoding = outputEncoding;
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
