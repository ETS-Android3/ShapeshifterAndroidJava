package org.operatorfoundation.shadow;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.Timeout;
import org.junit.runner.RunWith;
import org.libsodium.jni.NaCl;
import org.libsodium.jni.Sodium;
import org.operatorfoundation.shapeshifter.shadow.java.ShadowConfig;
import org.operatorfoundation.shapeshifter.shadow.java.ShadowSocket;

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

    @Rule
    public Timeout globalTimeout = new Timeout(20 * 1000); // 20 seconds

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

    @Test
    public void shadowSocketDemoServerTest() throws IOException, NoSuchAlgorithmException {
        ShadowConfig config = new ShadowConfig("1234", "AES-128-GCM");
        ShadowSocket shadowSocket = new ShadowSocket(config, "", 2346);
        assertNotNull(shadowSocket);
        String httpRequest = "GET / HTTP/1.0\r\n\r\n";
        byte[] textBytes = httpRequest.getBytes();
        shadowSocket.getOutputStream().write(textBytes);
        shadowSocket.getOutputStream().flush();
        byte[] buffer = new byte[244];
        shadowSocket.getInputStream().read(buffer);
    }

    @Test
    public void shadowSocketDemoServerTestChaCha() throws IOException, NoSuchAlgorithmException {

        Sodium sodium = NaCl.sodium();

        ShadowConfig config = new ShadowConfig("1234", "CHACHA20-IETF-POLY1305");
        ShadowSocket shadowSocket = new ShadowSocket(config, "", 2345);
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
        ShadowSocket shadowSocket = new ShadowSocket(config, "", 2346);
        assertNotNull(shadowSocket);
        String httpRequest = "GET / HTTP/1.0\r\n\r\n";
        byte[] textBytes = httpRequest.getBytes();
        shadowSocket.getOutputStream().write(textBytes);
        shadowSocket.getOutputStream().flush();
        byte[] buffer = new byte[0];
        shadowSocket.getInputStream().read(buffer);
    }

    @Test(expected = IOException.class)
    public void wrongServerConfigTest() throws IOException, NoSuchAlgorithmException {
        ShadowConfig config = new ShadowConfig("1234", "AES-128-GCM");
        ShadowSocket shadowSocket = new ShadowSocket(config, "", 2345);
        assertNotNull(shadowSocket);
        String httpRequest = "GET / HTTP/1.0\r\n\r\n";
        byte[] textBytes = httpRequest.getBytes();
        shadowSocket.getOutputStream().write(textBytes);
        shadowSocket.getOutputStream().flush();
        byte[] buffer = new byte[244];
        shadowSocket.getInputStream().read(buffer);
    }

    @Test
    public void shadowDarkStarServerTest() throws IOException, NoSuchAlgorithmException {
        ShadowConfig config = new ShadowConfig("3059301306072A8648CE3D020106082A8648CE3D030107034200041FF393BB8D976A5098F4D88853F7EA7A47DF7E1717A7E18084F3E3CA8D0FA9ACFB0F0E18801638712006B041880C0A15D227614E255728FF06EC8B7E466E19D4", "DarkStar");
        ShadowSocket shadowSocket = new ShadowSocket(config, "127.0.0.1", 1234);
        assertNotNull(shadowSocket);
        String httpRequest = "GET / HTTP/1.0\r\n\r\n";
        byte[] textBytes = httpRequest.getBytes();
        shadowSocket.getOutputStream().write(textBytes);
        shadowSocket.getOutputStream().flush();
        byte[] buffer = new byte[5];
        shadowSocket.getInputStream().read(buffer);
    }
}