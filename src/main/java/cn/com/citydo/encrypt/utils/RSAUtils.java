package cn.com.citydo.encrypt.utils;

import com.alibaba.fastjson.JSONObject;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

/**
 * RSA加解密工具类，实现公钥加密私钥解密和私钥解密公钥解密
 */
public class RSAUtils {

    private static final Integer MAX_ENCRYPT_BLOCK = 117;

    private static final String src = "abcdefghijklmnopqrstuvwxyz";

    private static final String piblicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDFx9vFGhHoLzvYIl8zd51WhAbaMN5q7WJVGr89lVLjpSCFsiTDHDpFplYu89oFgXNFERGHOkME+it2lNk676VFgy+ED5c0Rev2dVQgFqWhSOK8EICLpOwAyygzM/eBI5y/VT2L/81SSdMvePpxBW+2IKxVU+czkRgYp2d4u01jRwIDAQAB";
    private static final String privateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAMXH28UaEegvO9giXzN3nVaEBtow3mrtYlUavz2VUuOlIIWyJMMcOkWmVi7z2gWBc0UREYc6QwT6K3aU2TrvpUWDL4QPlzRF6/Z1VCAWpaFI4rwQgIuk7ADLKDMz94EjnL9VPYv/zVJJ0y94+nEFb7YgrFVT5zORGBinZ3i7TWNHAgMBAAECgYBGS3N8CXkF2gveFNFbXI8qWcCJukbDIF4Lu3bvL2yHhoAZpKhWRGkdqjIFfBwoSssqaBefxYBee4AJJHxU6yoE+8KpokIjDOU0vwIXfeyaWhnxy1jRKoi+y3qQchZOXHssREoBigjUzPTot2MlyyJxktgkQ/gYCe/8CmWrMh/hiQJBAOiMiNAPQtGuwcN+NQUjEwEEFALyyotH8plj9qR4bGr22V2zI6FIk2gfphDyM6Dctn1AL0HVYwcIruy9yvMY2nsCQQDZub/QFGLuCwyqSXdRKl2V3ZSeYPwSKEcUEQQ6OXOgPlD5xMps49Nb8KWo1U7lw5n5SGVJSuNHEsPsYv4t5halAkBRSv9wrEURg+PccTwbpZ05F7HfLfy8H9Sg5p8L88UCx3RJGxxzfyl4lse42NJPg5iPxGZAv1W02cY8oERYIvINAkEAjEJQIhDwBl+R4iV/uwbq0P+0nS7nVB8kYvXvXj7ikOl0KuMucGV4JHNrlM8Ni5CtoVyU+1lF/uRE2QSQsCrYjQJAabEZssB5OXhy+1pGssZrGAltnOImztENkOWvy2CyVOk3L31PGW5UWMZ+bbWK03zQo3uAjOCUetrDpQ37gse12Q==";

    public static void main(String[] args) throws Exception {
        System.out.println("***************** 公钥加密私钥解密开始 *****************");
        List<Map> list = new LinkedList<>();
        HashMap<String, String> map = new HashMap<String, String>();
        map.put("id", "1");
        map.put("name", "zhangsan");
        map.put("age", "18");
        map.put("address", "ningbo");
        for (int i = 0; i < 10; i++) {
            list.add(map);
        }
        String json = JSONObject.toJSONString(list);
        String text1 = encryptByPublicKey(piblicKey, json);
        String text2 = decryptByPrivateKey(privateKey, text1);
        System.out.println("加密前：" + json);
        System.out.println("加密后：" + text1);
        System.out.println("解密后：" + text2);
    }


    /**
     * 公钥解密
     *
     * @param publicKeyText
     * @param text
     * @return
     * @throws Exception
     */
    public static String decryptByPublicKey(String publicKeyText, String text) throws Exception {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(Base64.decodeBase64(publicKeyText));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] result = cipher.doFinal(Base64.decodeBase64(text));
        return new String(result);
    }

    /**
     * 私钥加密
     *
     * @param privateKeyText
     * @param text
     * @return
     * @throws Exception
     */
    public static String encryptByPrivateKey(String privateKeyText, String text) throws Exception {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(privateKeyText));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] result = cipher.doFinal(text.getBytes());
        return Base64.encodeBase64String(result);
    }

    /**
     * 私钥解密
     *
     * @param privateKeyText
     * @param text
     * @return
     * @throws Exception
     */
    public static String decryptByPrivateKey(String privateKeyText, String text) throws Exception {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec5 = new PKCS8EncodedKeySpec(Base64.decodeBase64(privateKeyText));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec5);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] inputArray = Base64.decodeBase64(text.getBytes("UTF-8"));
        int inputLength = inputArray.length;
        System.out.println("加密字节数：" + inputLength);
        // 最大加密字节数，超出最大字节数需要分组加密
        int MAX_ENCRYPT_BLOCK = 128;
        // 标识
        int offSet = 0;
        byte[] resultBytes = {};
        byte[] cache;
        while (inputLength - offSet > 0) {
            if (inputLength - offSet > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(inputArray, offSet, MAX_ENCRYPT_BLOCK);
                offSet += MAX_ENCRYPT_BLOCK;
            } else {
                cache = cipher.doFinal(inputArray, offSet, inputLength - offSet);
                offSet = inputLength;
            }
            resultBytes = Arrays.copyOf(resultBytes, resultBytes.length + cache.length);
            System.arraycopy(cache, 0, resultBytes, resultBytes.length - cache.length, cache.length);
        }
        return new String(resultBytes);
    }

    /**
     * 公钥加密
     *
     * @param publicKeyText
     * @param text
     * @return
     */
    public static String encryptByPublicKey(String publicKeyText, String text) throws Exception {
        X509EncodedKeySpec x509EncodedKeySpec2 = new X509EncodedKeySpec(Base64.decodeBase64(publicKeyText));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec2);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] bytes = text.getBytes();
        int length = bytes.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] cache;
        int offset = 0;
        int i = 0;
        while (length - offset > 0) {
            if (length - offset > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(bytes, offset, MAX_ENCRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(bytes, offset, length - offset);
            }
            out.write(cache, 0, cache.length);
            i++;
            offset = i * MAX_ENCRYPT_BLOCK;
        }
        byte[] result = out.toByteArray();
        out.close();
        return Base64.encodeBase64String(result);
    }


}