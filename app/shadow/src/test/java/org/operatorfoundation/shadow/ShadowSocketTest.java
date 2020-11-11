package org.operatorfoundation.shadow;


import android.app.Service;

import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.tls.Chacha20Poly1305;
import org.bouncycastle.jcajce.spec.AEADParameterSpec;
import org.junit.Test;
import org.libsodium.jni.NaCl;
import org.libsodium.jni.Sodium;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.TreeSet;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class ShadowSocketTest {

    @Test
    public void shadowSocketInitTest() throws IOException, NoSuchAlgorithmException {
        String password = "1234";
        ShadowConfig config = new ShadowConfig(password, "AES-128-GCM");
        ShadowSocket shadowSocket = new ShadowSocket(config, "127.0.0.1", 2222);
        assertNotNull(shadowSocket);
    }

    @Test
    public void shadowSocketWriteTest() throws IOException, NoSuchAlgorithmException {
        TestServer myRunnable = new TestServer();
        Thread thread = new Thread(myRunnable);
        thread.start();
        String password = "1234";
        ShadowConfig config = new ShadowConfig(password, "AES-128-GCM");
        ShadowSocket shadowSocket = new ShadowSocket(config, "127.0.0.1", 2222);
        assertNotNull(shadowSocket);
        String plaintext = "Hi";
        byte[] textBytes = plaintext.getBytes();
        shadowSocket.getOutputStream().write(textBytes);
        shadowSocket.getOutputStream().flush();
    }

    @Test
    public void shadowSocketReadTestAES128() throws IOException, NoSuchAlgorithmException {
        TestServer myRunnable = new TestServer();
        Thread thread = new Thread(myRunnable);
        thread.start();
        String password = "1234";
        ShadowConfig config = new ShadowConfig(password, "AES-128-GCM");
        ShadowSocket shadowSocket = new ShadowSocket(config, "127.0.0.1", 2222);
        assertNotNull(shadowSocket);
        String plaintext = "Hi";
        byte[] textBytes = plaintext.getBytes();
        shadowSocket.getOutputStream().write(textBytes);
        shadowSocket.getOutputStream().flush();
        byte[] buffer = new byte[2];
        shadowSocket.getInputStream().read(buffer);
        assertEquals("Yo", new String(buffer));
    }

    @Test
    public void shadowSocketReadTestAES256() throws IOException, NoSuchAlgorithmException {
        TestServer myRunnable = new TestServer();
        Thread thread = new Thread(myRunnable);
        thread.start();
        String password = "1234";
        ShadowConfig config = new ShadowConfig(password, "AES-256-GCM");
        ShadowSocket shadowSocket = new ShadowSocket(config, "127.0.0.1", 2222);
        assertNotNull(shadowSocket);
        String plaintext = "Hi";
        byte[] textBytes = plaintext.getBytes();
        shadowSocket.getOutputStream().write(textBytes);
        shadowSocket.getOutputStream().flush();
        byte[] buffer = new byte[2];
        shadowSocket.getInputStream().read(buffer);
        assertEquals("Yo", new String(buffer));
    }

    @Test
    public void shadowSocketReadTestCHACHA() throws IOException, NoSuchAlgorithmException, IllegalArgumentException {

        TestServer myRunnable = new TestServer();
        Thread thread = new Thread(myRunnable);
        thread.start();
        String password = "1234";
        ShadowConfig config = new ShadowConfig(password, "CHACHA20-IETF-POLY1305");
        ShadowSocket shadowSocket = new ShadowSocket(config, "127.0.0.1", 2222);
        assertNotNull(shadowSocket);
        String plaintext = "Hi";
        byte[] textBytes = plaintext.getBytes();
        shadowSocket.getOutputStream().write(textBytes);
        shadowSocket.getOutputStream().flush();
        byte[] buffer = new byte[2];
        shadowSocket.getInputStream().read(buffer);
        assertEquals("Yo", new String(buffer));
    }

    @Test
    public void algorythmFinder() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        TreeSet<String> algs = new TreeSet<>();
        for (Provider provider : Security.getProviders()) {
//            provider.getServices().stream()
//                    .filter(s -> "Cipher".equals(s.getType()))
//                    .map(Service::getAlgorithm)
//                    .forEach(algs::add);
            System.out.println(provider);
            for (java.security.Provider.Service service : provider.getServices()) {
                if (service.getType().equals("Cipher")) {
                    System.out.println(service);
                    System.out.println(service.getAlgorithm());
                }
            }
        }

        algs.stream().forEach(System.out::println);
    }

    @Test
    public void bouncyCastleTest() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Cipher cipher = Cipher.getInstance("CHACHA7539");
        byte[] bytes = {
                0,0,0,0,0,0,0,0,0,0,0,0
        };
        AlgorithmParameterSpec ivSpec = new AEADParameterSpec(bytes, 128);
        byte[] keyBytes = {
                1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2
        };
        SecretKey key = new SecretKeySpec(keyBytes, "ChaCha20");
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] plainText = {
                1
        };
        byte[] encrypted = cipher.doFinal(plainText);
        System.out.println(cipher.getClass());
        System.out.println(encrypted.length);
    }

    @Test
    public void chaChaTest() throws IOException, NoSuchAlgorithmException {
        TestServer myRunnable = new TestServer();
        Thread thread = new Thread(myRunnable);
        thread.start();
        String password = "1234";
        ShadowConfig config = new ShadowConfig(password, "CHACHA20-IETF-POLY1305");
        ShadowSocket shadowSocket = new ShadowSocket(config, "127.0.0.1", 2222);
        assertNotNull(shadowSocket);
        String plaintext = "Hi";
        byte[] textBytes = plaintext.getBytes();
        shadowSocket.getOutputStream().write(textBytes);
        shadowSocket.getOutputStream().flush();
        byte[] buffer = new byte[2];
        shadowSocket.getInputStream().read(buffer);
        assertEquals("Yo", new String(buffer));
    }

    @Test
    public void libsodiumTest() {
        String message = "Test Message";
        Sodium sodium = NaCl.sodium();

        byte[] nonce = new byte[Sodium.crypto_aead_chacha20poly1305_npubbytes()];
        byte[] key = new byte[Sodium.crypto_aead_chacha20poly1305_keybytes()];
        Sodium.randombytes_buf(nonce, nonce.length);
        Sodium.randombytes_buf(key, key.length);

        int mlen = message.length();
        int[] clen_p = new int[0];
        byte[] c = new byte[mlen + Sodium.crypto_aead_chacha20poly1305_abytes()];

        int encryptReturn = Sodium.crypto_aead_chacha20poly1305_encrypt(c, clen_p, message.getBytes(), mlen, new byte[0], 0, new byte[0], nonce, key);

        assertEquals(0, encryptReturn);

        byte[] m = new byte[message.length()];

        int[] mlen_p = new int[1];

        Sodium.crypto_aead_chacha20poly1305_decrypt(m, mlen_p, new byte[0], c, c.length, new byte[0], 0, nonce, key);
        assertEquals(message, new String(m));
    }

}

