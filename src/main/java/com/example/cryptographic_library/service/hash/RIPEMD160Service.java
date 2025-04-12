package com.example.cryptographic_library.service.hash;

import com.example.cryptographic_library.algorithm.encode.Base64;
import com.example.cryptographic_library.algorithm.encode.UTF_8;
import com.example.cryptographic_library.algorithm.hash.RIPEMD160;
import com.example.cryptographic_library.dto.hash.RIPEMD160Response;
import org.springframework.stereotype.Service;

/**
 * RIPEMD-160哈希服务实现
 *
 * <p>功能特性：
 * <ul>
 *   <li>支持任意长度输入数据</li>
 *   <li>输出格式可选Hex或Base64</li>
 *   <li>严格输入数据校验</li>
 * </ul>
 */
@Service
public class RIPEMD160Service {

    /**
     * 执行哈希计算
     * @param data 原始输入字符串（UTF-8 编码）
     * @param encoding 输出编码格式（hex/base64）
     * @return 哈希结果响应（固定20 字节的哈希值）
     * @throws IllegalArgumentException 输入为空或编码格式不支持时抛出
     */
    public RIPEMD160Response hash(String data, String encoding) {
        try {
            validateInput(data, encoding);
            byte[] hashBytes = computeRipemd160(data);
            return new RIPEMD160Response(0, "哈希计算成功", encodeResult(hashBytes, encoding));
        } catch (IllegalArgumentException e) {
            return new RIPEMD160Response(-1, e.getMessage(), null);
        } catch (Exception e) {
            return new RIPEMD160Response(-2, "服务器处理错误", null);
        }
    }

    private byte[] computeRipemd160(String data) {
        RIPEMD160 md = new RIPEMD160();
        md.update(UTF_8.encode(data));
        return md.digest();
    }

    private void validateInput(String data, String encoding) {
        if (data == null) {
            throw new IllegalArgumentException("输入数据不能为空");
        }
        if (!"hex".equalsIgnoreCase(encoding) && !"base64".equalsIgnoreCase(encoding)) {
            throw new IllegalArgumentException("不支持的编码格式: " + encoding);
        }
    }

    private String encodeResult(byte[] data, String encoding) {
        if ("base64".equalsIgnoreCase(encoding)) {
            return Base64.encode(data);
        }
        return bytesToHex(data);
    }

    private static final char[] HEX_ARRAY = "0123456789abcdef".toCharArray();
    private String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            hexChars[i * 2] = HEX_ARRAY[v >>> 4];
            hexChars[i * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }
}
