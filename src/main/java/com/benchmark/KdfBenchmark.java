package com.benchmark;

import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.spec.KeySpec;

public abstract class KdfBenchmark extends CryptoBenchmark {

    protected char[] password;
    protected byte[] salt;

    protected void commonSetup() throws Exception {
        initProvider();
        password = "password".toCharArray();
        salt = new byte[16]; // 128-bit salt
    }

    public static class Pbkdf2 extends KdfBenchmark {
        @Param({
            // SHA2 Variants
            "PBKDF2WithHmacSHA224",
            "PBKDF2WithHmacSHA256", 
            "PBKDF2WithHmacSHA384", 
            "PBKDF2WithHmacSHA512",
            // SHA512 Truncated Variants
            "PBKDF2WithHmacSHA512-224", 
            "PBKDF2WithHmacSHA512-256",
             // SHA-3 Variants
            "PBKDF2WithHmacSHA3-224", 
            "PBKDF2WithHmacSHA3-256", 
            "PBKDF2WithHmacSHA3-384", 
            "PBKDF2WithHmacSHA3-512",
            // SM3
            "PBKDF2WithHmacSM3"
        })
        public String algorithm;

        @Param({"1000", "10000"})
        public int iterations;

        @Setup(Level.Trial)
        public void setup() throws Exception {
            super.commonSetup();
        }

        @Benchmark
        public void deriveKey(Blackhole bh) throws Exception {
            SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithm, provider);
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, 256);
            bh.consume(skf.generateSecret(spec));
        }
    }

    public static class Scrypt extends KdfBenchmark {
        
        // N = CPU/memory cost parameter (must be power of 2)
        @Param({"16384", "32768"}) 
        public int N;

        @Setup(Level.Trial)
        public void setup() throws Exception {
            super.commonSetup();
        }

        @Benchmark
        public void deriveKey(Blackhole bh) throws Exception {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("SCRYPT", provider);
            
            KeySpec spec;
            // Fixed parameters: r=8, p=1, keyLen=256
            int r = 8;
            int p = 1;
            int keyLen = 256;

            if ("BC".equalsIgnoreCase(providerName)) {
                spec = new org.bouncycastle.jcajce.spec.ScryptKeySpec(password, salt, N, r, p, keyLen);
            } else {
                 // OpenSSL Jostle provider
                spec = new org.openssl.jostle.jcajce.spec.ScryptKeySpec(password, salt, N, r, p, keyLen);
            }
            bh.consume(skf.generateSecret(spec));
        }
    }
}
