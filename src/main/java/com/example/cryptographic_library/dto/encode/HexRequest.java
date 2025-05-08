package com.example.cryptographic_library.dto.encode;

public class HexRequest {
    private String data;

    public HexRequest(String data) {
        this.data = data;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }
}
