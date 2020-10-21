package org.operatorfoundation.shadow;


import org.junit.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.assertNotNull;

class ShadowSocketTest {

    @Test
    public void shadowSocketInitTest() throws IOException, NoSuchAlgorithmException {
        String password = "1234";
        ShadowConfig config = new ShadowConfig(password, "AES-128-GCM");
        ShadowSocket shadowSocket = new ShadowSocket(config, "127.0.0.1", 2222);
        assertNotNull (shadowSocket);
    }

    @Test
    public void shadowSocketWriteTest() throws IOException, NoSuchAlgorithmException {
        String password = "1234";
        ShadowConfig config = new ShadowConfig(password, "AES-128-GCM");
        ShadowSocket shadowSocket = new ShadowSocket(config, "127.0.0.1", 2222);
        assertNotNull (shadowSocket);
        String plaintext = "Hi";
        byte[] textBytes = plaintext.getBytes();
        shadowSocket.getOutputStream().write(textBytes);
        shadowSocket.getOutputStream();
    }

    @Test
    public void shadowSocketReadTest() throws IOException, NoSuchAlgorithmException {
        String password = "1234";
        ShadowConfig config = new ShadowConfig(password, "AES-128-GCM");
        ShadowSocket shadowSocket = new ShadowSocket(config, "127.0.0.1", 2222);
        assertNotNull (shadowSocket);
    }
}