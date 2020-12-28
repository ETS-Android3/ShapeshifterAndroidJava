package org.operatorfoundation.shadow;

import android.content.Context;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.libsodium.jni.NaCl;
import org.libsodium.jni.Sodium;
import org.operatorfoundation.shapeshifter.shadow.java.ShadowCipher;
import org.operatorfoundation.shapeshifter.shadow.java.ShadowConfig;
import org.operatorfoundation.shapeshifter.shadow.java.ShadowSocket;
import org.operatorfoundation.shapeshifter.shadow.java.TestServer;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * Instrumented test, which will execute on an Android device.
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
@RunWith(AndroidJUnit4.class)
public class ExampleInstrumentedTest {
    @Test
    public void libsodiumTest() {
        String message = "Te";
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

    @Test
    public void libsodiumTestTheSequel() {
        String message = "Te";
        Sodium sodium = NaCl.sodium();

        byte[] nonce = new byte[Sodium.crypto_aead_chacha20poly1305_ietf_npubbytes()];
        byte[] key = new byte[Sodium.crypto_aead_chacha20poly1305_ietf_keybytes()];
        Sodium.randombytes_buf(nonce, nonce.length);
        Sodium.randombytes_buf(key, key.length);

        int mlen = message.length();
        int[] clen_p = new int[0];
        byte[] c = new byte[mlen + Sodium.crypto_aead_chacha20poly1305_ietf_abytes()];

        int encryptReturn = Sodium.crypto_aead_chacha20poly1305_ietf_encrypt(c, clen_p, message.getBytes(), mlen, new byte[0], 0, new byte[0], nonce, key);

        assertEquals(0, encryptReturn);

        byte[] m = new byte[message.length()];

        int[] mlen_p = new int[1];

        Sodium.crypto_aead_chacha20poly1305_ietf_decrypt(m, mlen_p, new byte[0], c, c.length, new byte[0], 0, nonce, key);
        assertEquals(message, new String(m));
    }

//@Test
//public void ShadowConnect(Context applicationContext) throws IOException {
//    try{
//
//        ShadowConfig config = new ShadowConfig("1234", "AES-128-GCM");
//        ShadowSocket socket = new ShadowSocket(config,"1234", 2222);
//        //**********************Operaotor************
//        String plaintext = "GET / HTTP/1.0\r\n\r\n";
//        byte[] textBytes = plaintext.getBytes();
//        try {
//            socket.getOutputStream().write(textBytes);
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//        try {
//            socket.getOutputStream().flush();
//            byte[] textOutput = new byte[2];
//            System.out.println("Output.before read"+textOutput.toString());
//            socket.getInputStream().read(textOutput); 			System.out.println("Output after read"+textOutput.toString());
//
//            socket.close();
//
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//    } catch (NoSuchAlgorithmException e) {
//        e.printStackTrace();
//    }
//
//}

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
    public void socketInitTest() throws IOException, NoSuchAlgorithmException {
        String password = "1234";
        ShadowConfig config = new ShadowConfig(password, "AES-128-GCM");
        ShadowSocket shadowSocket = new ShadowSocket(config, "127.0.0.1", 2222);
        assertNotNull(shadowSocket);
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
    public void shadowSocketDemoServerTest() throws IOException, NoSuchAlgorithmException {
//        TestServer myRunnable = new TestServer();
//        Thread thread = new Thread(myRunnable);
//        thread.start();
        ShadowConfig config = new ShadowConfig("1234", "AES-128-GCM");
        ShadowSocket shadowSocket = new ShadowSocket(config, "159.203.158.90", 2346);
        assertNotNull(shadowSocket);
        String httpRequest = "GET / HTTP/1.0\r\n\r\n";
        byte[] textBytes = httpRequest.getBytes();
        shadowSocket.getOutputStream().write(textBytes);
        shadowSocket.getOutputStream().flush();
        byte[] buffer = new byte[244];
        shadowSocket.getInputStream().read(buffer);
        System.out.println(new String(buffer));
        //assertEquals("Yo", new String(buffer));
    }

    @Test
    public void shadowSocketDemoServerTestChaCha() throws IOException, NoSuchAlgorithmException {
//        TestServer myRunnable = new TestServer();
//        Thread thread = new Thread(myRunnable);
//        thread.start();

        Sodium sodium = NaCl.sodium();

        ShadowConfig config = new ShadowConfig("1234", "CHACHA20-IETF-POLY1305");
        ShadowSocket shadowSocket = new ShadowSocket(config, "159.203.158.90", 2345);
        assertNotNull(shadowSocket);
        String httpRequest = "GET / HTTP/1.0\r\n\r\n";
        byte[] textBytes = httpRequest.getBytes();
        shadowSocket.getOutputStream().write(textBytes);
        shadowSocket.getOutputStream().flush();
        byte[] buffer = new byte[244];
        shadowSocket.getInputStream().read(buffer);
        String decryptedString = (new String(buffer));
        //assertEquals("Yo", new String(buffer));
    }

    @Test
    public void badBufferSizeTest() throws IOException, NoSuchAlgorithmException {
        ShadowConfig config = new ShadowConfig("1234", "AES-128-GCM");
        ShadowSocket shadowSocket = new ShadowSocket(config, "159.203.158.90", 2346);
        assertNotNull(shadowSocket);
        String httpRequest = "GET / HTTP/1.0\r\n\r\n";
        byte[] textBytes = httpRequest.getBytes();
        shadowSocket.getOutputStream().write(textBytes);
        shadowSocket.getOutputStream().flush();
        byte[] buffer = new byte[0];
        shadowSocket.getInputStream().read(buffer);
        System.out.println(new String(buffer));
    }

    @Test
    public void wrongServerConfigTest() throws IOException, NoSuchAlgorithmException {
        ShadowConfig config = new ShadowConfig("1234", "AES-128-GCM");
        ShadowSocket shadowSocket = new ShadowSocket(config, "159.203.158.90", 2345);
        assertNotNull(shadowSocket);
        String httpRequest = "GET / HTTP/1.0\r\n\r\n";
        byte[] textBytes = httpRequest.getBytes();
        shadowSocket.getOutputStream().write(textBytes);
        shadowSocket.getOutputStream().flush();
        byte[] buffer = new byte[244];
        shadowSocket.getInputStream().read(buffer);
        System.out.println(new String(buffer));
    }

}