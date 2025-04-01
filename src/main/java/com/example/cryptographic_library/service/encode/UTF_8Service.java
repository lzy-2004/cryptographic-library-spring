package com.example.cryptographic_library.service.encode;

import com.example.cryptographic_library.algorithm.encode.UTF_8;
import com.example.cryptographic_library.dto.encode.UTF_8Response;
import org.springframework.stereotype.Service;

@Service
public class UTF_8Service {
    public UTF_8Response encode(String data, String encoding) {
        try {
            UTF_8 utf_8 = new UTF_8();
            byte[] encoded = utf_8.encode(data); // 修改点2

            if(encoding.equals("hex")){
                return new UTF_8Response(0, "编码成功", bytesToHex(encoded));
            }else if(encoding.equals("binary")){
                return new UTF_8Response(0, "编码成功", bytesToBinary(encoded));
            }else if(encoding.equals("octal")){
                return new UTF_8Response(0, "编码成功", bytesToOctal(encoded));
            }else if(encoding.equals("decimal")){
                return new UTF_8Response(0, "编码成功", bytesToDecimal(encoded));
            }else{
                return new UTF_8Response(-1, "编码方式不支持", null);
            }
        } catch (Exception e) {
            return new UTF_8Response(-1, "编码失败: " + e.getMessage(), null);
        }
    }

    public UTF_8Response decode(String data,String encoding) {
        try {
            UTF_8 utf_8 = new UTF_8();
            String decoded = "";
            if(encoding.equals("hex")){
                decoded = utf_8.decode(hexToBytes(data));
            }else if(encoding.equals("binary")){
                decoded = utf_8.decode(binaryToBytes(data));
            }else if(encoding.equals("octal")){
                decoded = utf_8.decode(octalToBytes(data));
            }else if(encoding.equals("decimal")){
                decoded = utf_8.decode(decimalToBytes(data));
            }
            return new UTF_8Response(0, "解码成功", decoded);
        } catch (Exception e) {
            return new UTF_8Response(-1, "解码失败: " + e.getMessage(), null);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }
    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i/2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }

    public static String bytesToBinary(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0'))
                    .append(" ");
        }
        return sb.toString().trim();
    }
    public static byte[] binaryToBytes(String binaryStr) {
        String[] parts = binaryStr.split("\\s+");
        byte[] result = new byte[parts.length];
        for (int i = 0; i < parts.length; i++) {
            if (parts[i].length() > 8) {
                throw new IllegalArgumentException("每个二进制段长度不能超过8位");
            }
            result[i] = (byte) Integer.parseInt(parts[i], 2);
        }
        return result;
    }
    public static String bytesToOctal(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%3s", Integer.toOctalString(b & 0xFF)).replace(' ', '0'))
                    .append(" ");
        }
        return sb.toString().trim();
    }
    public static byte[] octalToBytes(String octalStr) {
        String[] parts = octalStr.split("\\s+");
        byte[] result = new byte[parts.length];
        for (int i = 0; i < parts.length; i++) {
            if (parts[i].length() > 3) {
                throw new IllegalArgumentException("每个八进制段长度不能超过3位");
            }
            result[i] = (byte) Integer.parseInt(parts[i], 8);
        }
        return result;
    }
    public static String bytesToDecimal(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(b & 0xFF).append(" ");
        }
        return sb.toString().trim();
    }
    public static byte[] decimalToBytes(String decimalStr) {
        String[] parts = decimalStr.split("\\s+");
        byte[] result = new byte[parts.length];
        for (int i = 0; i < parts.length; i++) {
            int value = Integer.parseInt(parts[i]);
            if (value < 0 || value > 255) {
                throw new IllegalArgumentException("每个十进制值必须在0-255范围内");
            }
            result[i] = (byte) value;
        }
        return result;
    }
}
