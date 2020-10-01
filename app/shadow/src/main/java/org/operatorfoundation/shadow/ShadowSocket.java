package org.operatorfoundation.shadow;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Proxy;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.NoSuchPaddingException;

public class ShadowSocket {
    static Socket socket = new Socket();
    static ShadowCipher encryptionCipher;
    static ShadowCipher decryptionCipher;
    static Boolean connectionStatus;

    public ShadowSocket(ShadowConfig config) {
        // Init block
        {
            // Create salt for encryptionCipher
            byte[] salt = ShadowCipher.createSalt(config);
            // Create an encryptionCipher
            encryptionCipher = new ShadowCipher(config, salt);
        }
    }

    ShadowSocket(ShadowConfig config, String host, int port) throws IOException {
        this(config);
        socket = new Socket(host, port);
        connectionStatus = true;
        handshake();
    }

    ShadowSocket(ShadowConfig config, String host, int port, InetAddress localAddr, int localPort) throws IOException {
        this(config);
        socket = new Socket(host, port, localAddr, localPort);
        connectionStatus = true;
        handshake();
    }

    ShadowSocket(ShadowConfig config, InetAddress address, int port) throws IOException {
        this(config);
        socket = new Socket(address, port);
        connectionStatus = true;
        handshake();
    }

    ShadowSocket(ShadowConfig config, InetAddress address, int port, InetAddress localAddr, int localPort) throws IOException {
        this(config);
        socket = new Socket(address, port, localAddr, localPort);
        connectionStatus = true;
        handshake();
    }

    ShadowSocket(ShadowConfig config, Proxy proxy) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        this(config);
        socket = new Socket(proxy);
    }


    private void handshake() {
        sendSalt();
        receiveSalt();
    }
    private void sendSalt() {

    }

    private void receiveSalt() {

    }
}
