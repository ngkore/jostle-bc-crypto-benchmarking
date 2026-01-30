package com.benchmark;

import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.AlgorithmParameterSpec;
import java.security.NoSuchAlgorithmException;

public abstract class SymmetricBenchmark extends CryptoBenchmark {

    protected SecretKey key;
    protected byte[] data;
    protected byte[] encryptedData;
    protected AlgorithmParameterSpec params;
    protected String transform;

    protected void commonSetup(String transform, int keySize) throws Exception {
        this.transform = transform;
        initProvider();

        String[] parts = transform.split("/");
        String algorithm = parts[0];
        String mode = parts[1];
        
        KeyGenerator kg = null;
        try {
            kg = KeyGenerator.getInstance(algorithm, provider);
        } catch (NoSuchAlgorithmException e) {
        }

        if (kg != null) {
            kg.init(keySize);
            key = kg.generateKey();
        } else {
            byte[] keyBytes = new byte[keySize / 8];
            new java.security.SecureRandom().nextBytes(keyBytes);
            key = new SecretKeySpec(keyBytes, algorithm.toUpperCase());
        }

        data = new byte[1024]; 
        new java.security.SecureRandom().nextBytes(data);

        if ("GCM".equalsIgnoreCase(mode) || "CCM".equalsIgnoreCase(mode)|| "OCB".equalsIgnoreCase(mode)) {
            byte[] nonce = new byte[12]; 
            new java.security.SecureRandom().nextBytes(nonce);
            params = new GCMParameterSpec(128, nonce);
        } else if (mode.contains("CBC") || mode.contains("CTR") 
                || mode.contains("OFB") || mode.contains("CFB")) {
            byte[] iv = new byte[16];
            new java.security.SecureRandom().nextBytes(iv);
            params = new IvParameterSpec(iv);
        } else {
            params = null;
        }

        Cipher encryptCipher = Cipher.getInstance(transform, provider);
        if (params != null) {
            encryptCipher.init(Cipher.ENCRYPT_MODE, key, params);
        } else {
            encryptCipher.init(Cipher.ENCRYPT_MODE, key);
        }
        encryptedData = encryptCipher.doFinal(data);
    }

    @Benchmark
    public void encrypt(Blackhole bh) throws Exception {
        Cipher cipher = Cipher.getInstance(transform, provider);
        if (params != null) {
            cipher.init(Cipher.ENCRYPT_MODE, key, params);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, key);
        }
        bh.consume(cipher.doFinal(data));
    }

    @Benchmark
    public void decrypt(Blackhole bh) throws Exception {
        Cipher cipher = Cipher.getInstance(transform, provider);
        if (params != null) {
            cipher.init(Cipher.DECRYPT_MODE, key, params);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, key);
        }
        bh.consume(cipher.doFinal(encryptedData));
    }

    public static class Aes extends SymmetricBenchmark {
        @Param({
            // AEAD
            "AES/GCM/NoPadding",
            /* "AES/CCM/NoPadding", */ 
            /* "AES/OCB/NoPadding", */
            // Block
            "AES/ECB/NoPadding", "AES/ECB/PKCS5Padding", "AES/ECB/PKCS7Padding",
            "AES/CBC/NoPadding", "AES/CBC/PKCS5Padding", "AES/CBC/PKCS7Padding",
            // Stream
            "AES/CTR/NoPadding",
            "AES/OFB/NoPadding",
            "AES/CFB128/NoPadding"
        })
        public String transform;

        @Param({"128", "192", "256"})
        public int keySize;

        @Setup(Level.Trial)
        public void setup() throws Exception {
            super.commonSetup(transform, keySize);
        }
    }

    public static class Aria extends SymmetricBenchmark {
        @Param({
            // AEAD
            // "ARIA/GCM/NoPadding",
            // "ARIA/CCM/NoPadding",
            // Block
            "ARIA/ECB/NoPadding", "ARIA/ECB/PKCS5Padding", "ARIA/ECB/PKCS7Padding",
            "ARIA/CBC/NoPadding", "ARIA/CBC/PKCS5Padding", "ARIA/CBC/PKCS7Padding",
            // Stream
            "ARIA/CTR/NoPadding",
            "ARIA/OFB/NoPadding",
            "ARIA/CFB128/NoPadding"
        })
        public String transform;

        @Param({"128", "192", "256"})
        public int keySize;

        @Setup(Level.Trial)
        public void setup() throws Exception {
            super.commonSetup(transform, keySize);
        }
    }

    public static class Camellia extends SymmetricBenchmark {
        @Param({
            // Block
            "Camellia/ECB/NoPadding", "Camellia/ECB/PKCS5Padding", "Camellia/ECB/PKCS7Padding",
            "Camellia/CBC/NoPadding", "Camellia/CBC/PKCS5Padding", "Camellia/CBC/PKCS7Padding",
            // Stream
            "Camellia/CTR/NoPadding",
            "Camellia/OFB/NoPadding",
            "Camellia/CFB128/NoPadding"
        })
        public String transform;

        @Param({"128", "192", "256"})
        public int keySize;

        @Setup(Level.Trial)
        public void setup() throws Exception {
            super.commonSetup(transform, keySize);
        }
    }

    public static class Sm4 extends SymmetricBenchmark {
        @Param({
            // Block
            "SM4/ECB/NoPadding", "SM4/ECB/PKCS5Padding", "SM4/ECB/PKCS7Padding",
            "SM4/CBC/NoPadding", "SM4/CBC/PKCS5Padding", "SM4/CBC/PKCS7Padding",
            // Stream
            "SM4/CTR/NoPadding",
            "SM4/OFB/NoPadding",
            "SM4/CFB128/NoPadding"
        })
        public String transform;

        @Param({"128"})
        public int keySize;

        @Setup(Level.Trial)
        public void setup() throws Exception {
            super.commonSetup(transform, keySize);
        }
    }
}
