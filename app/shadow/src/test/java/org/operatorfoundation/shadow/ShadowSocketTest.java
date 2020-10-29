package org.operatorfoundation.shadow;


import org.junit.Test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

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
    public void shadowSocketReadTest() throws IOException, NoSuchAlgorithmException {
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
        assertEquals("Yo", Arrays.toString(buffer));
    }
}