package com.benchmark;

import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.SecureRandom;
import javax.crypto.KeyGenerator;

// Jostle Specific Imports
import org.openssl.jostle.jcajce.spec.KEMGenerateSpec;
import org.openssl.jostle.jcajce.spec.KEMExtractSpec;
import org.openssl.jostle.jcajce.SecretKeyWithEncapsulation;

public abstract class PqcBenchmark extends CryptoBenchmark {

    protected KeyPair keyPair;
    protected byte[] data;

    public static class MlDsa extends PqcBenchmark {
        @Param({
                "ML-DSA-44",
                "ML-DSA-65",
                "ML-DSA-87"
        })
        public String algorithm;

        private byte[] signature;

        @Setup(Level.Trial)
        public void setup() throws Exception {
            initProvider();
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, provider);
            keyPair = kpg.generateKeyPair();

            data = new byte[1024];
            new SecureRandom().nextBytes(data);

            // Pre-compute signature for verify benchmark
            Signature sig = Signature.getInstance(algorithm, provider);
            sig.initSign(keyPair.getPrivate());
            sig.update(data);
            signature = sig.sign();
        }

        @Benchmark
        public void keyGen(Blackhole bh) throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, provider);
            bh.consume(kpg.generateKeyPair());
        }

        @Benchmark
        public void sign(Blackhole bh) throws Exception {
            Signature sig = Signature.getInstance(algorithm, provider);
            sig.initSign(keyPair.getPrivate());
            sig.update(data);
            bh.consume(sig.sign());
        }

        @Benchmark
        public void verify(Blackhole bh) throws Exception {
            Signature sig = Signature.getInstance(algorithm, provider);
            sig.initVerify(keyPair.getPublic());
            sig.update(data);
            bh.consume(sig.verify(signature));
        }
    }

    public static class SlhDsa extends PqcBenchmark {
        @Param({
                // SHA2 Variants
                "SLH-DSA-SHA2-128S", "SLH-DSA-SHA2-128F",
                "SLH-DSA-SHA2-192S", "SLH-DSA-SHA2-192F",
                "SLH-DSA-SHA2-256S", "SLH-DSA-SHA2-256F",
                // SHAKE Variants
                "SLH-DSA-SHAKE-128S", "SLH-DSA-SHAKE-128F",
                "SLH-DSA-SHAKE-192S", "SLH-DSA-SHAKE-192F",
                "SLH-DSA-SHAKE-256S", "SLH-DSA-SHAKE-256F"
        })
        public String algorithm;

        private byte[] signature;

        @Setup(Level.Trial)
        public void setup() throws Exception {
            initProvider();
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, provider);
            keyPair = kpg.generateKeyPair();

            data = new byte[1024];
            new SecureRandom().nextBytes(data);

            Signature sig = Signature.getInstance(algorithm, provider);
            sig.initSign(keyPair.getPrivate());
            sig.update(data);
            signature = sig.sign();
        }

        @Benchmark
        public void keyGen(Blackhole bh) throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, provider);
            bh.consume(kpg.generateKeyPair());
        }

        @Benchmark
        public void sign(Blackhole bh) throws Exception {
            Signature sig = Signature.getInstance(algorithm, provider);
            sig.initSign(keyPair.getPrivate());
            sig.update(data);
            bh.consume(sig.sign());
        }

        @Benchmark
        public void verify(Blackhole bh) throws Exception {
            Signature sig = Signature.getInstance(algorithm, provider);
            sig.initVerify(keyPair.getPublic());
            sig.update(data);
            bh.consume(sig.verify(signature));
        }
    }

    public static class MlKem extends PqcBenchmark {
        @Param({
                "ML-KEM-512",
                "ML-KEM-768",
                "ML-KEM-1024"
        })
        public String algorithm;

        private byte[] encapsulation;

        @Setup(Level.Trial)
        public void setup() throws Exception {
            initProvider();

            KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, provider);
            keyPair = kpg.generateKeyPair();

            // Pre-compute encapsulation
            if ("Jostle".equalsIgnoreCase(providerName)) {
                KeyGenerator kg = KeyGenerator.getInstance("ML-KEM", provider);
                kg.init(KEMGenerateSpec.builder()
                        .withPublicKey(keyPair.getPublic())
                        .withKeySizeInBits(256)
                        .withAlgorithmName("AES")
                        .build());
                SecretKeyWithEncapsulation ske = (SecretKeyWithEncapsulation) kg.generateKey();
                encapsulation = ske.getEncapsulation();
            } else {
                // Bouncy Castle provider
                KeyGenerator kg = KeyGenerator.getInstance("ML-KEM", provider);
                kg.init(new org.bouncycastle.jcajce.spec.KEMGenerateSpec(keyPair.getPublic(), "AES"),
                        new SecureRandom());
                org.bouncycastle.jcajce.SecretKeyWithEncapsulation ske = (org.bouncycastle.jcajce.SecretKeyWithEncapsulation) kg
                        .generateKey();
                encapsulation = ske.getEncapsulation();
            }
        }

        @Benchmark
        public void keyGen(Blackhole bh) throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, provider);
            bh.consume(kpg.generateKeyPair());
        }

        @Benchmark
        public void encaps(Blackhole bh) throws Exception {
            if ("Jostle".equalsIgnoreCase(providerName)) {
                KeyGenerator kg = KeyGenerator.getInstance("ML-KEM", provider);
                kg.init(KEMGenerateSpec.builder()
                        .withPublicKey(keyPair.getPublic())
                        .withKeySizeInBits(256)
                        .withAlgorithmName("AES")
                        .build());
                bh.consume(kg.generateKey());
            } else {
                // Bouncy Castle provider
                KeyGenerator kg = KeyGenerator.getInstance("ML-KEM", provider);
                kg.init(new org.bouncycastle.jcajce.spec.KEMGenerateSpec(keyPair.getPublic(), "AES"),
                        new SecureRandom());
                bh.consume(kg.generateKey());
            }
        }

        @Benchmark
        public void decaps(Blackhole bh) throws Exception {
            if ("Jostle".equalsIgnoreCase(providerName)) {
                KeyGenerator kg = KeyGenerator.getInstance("ML-KEM", provider);
                kg.init(KEMExtractSpec.builder()
                        .withPrivate(keyPair.getPrivate())
                        .withAlgorithmName("AES")
                        .withKeySizeInBits(256)
                        .withEncapsulatedKey(encapsulation)
                        .build());
                bh.consume(kg.generateKey());
            } else {
                // Bouncy Castle provider
                KeyGenerator kg = KeyGenerator.getInstance("ML-KEM", provider);
                kg.init(new org.bouncycastle.jcajce.spec.KEMExtractSpec(keyPair.getPrivate(), encapsulation, "AES"),
                        new SecureRandom());
                bh.consume(kg.generateKey());
            }
        }
    }
}
