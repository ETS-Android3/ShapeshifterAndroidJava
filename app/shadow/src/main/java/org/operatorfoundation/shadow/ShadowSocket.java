package org.operatorfoundation.shadow;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Proxy;
import java.net.Socket;
import java.net.SocketAddress;
import java.nio.channels.SocketChannel;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.NoSuchPaddingException;

public class ShadowSocket {
    static Socket socket = new Socket();
    static ShadowCipher encryptionCipher;
    static ShadowCipher decryptionCipher;
    static Boolean connectionStatus;

    public ShadowSocket(ShadowConfig config) throws NoSuchAlgorithmException {
        // Init block
        {
            // Create salt for encryptionCipher
            byte[] salt = ShadowCipher.createSalt(config);
            // Create an encryptionCipher
            encryptionCipher = new ShadowCipher(config, salt);
        }
    }

    ShadowSocket(ShadowConfig config, String host, int port) throws IOException, NoSuchAlgorithmException {
        this(config);
        socket = new Socket(host, port);
        connectionStatus = true;
        handshake();
    }

    ShadowSocket(ShadowConfig config, String host, int port, InetAddress localAddr, int localPort) throws IOException, NoSuchAlgorithmException {
        this(config);
        socket = new Socket(host, port, localAddr, localPort);
        connectionStatus = true;
        handshake();
    }

    ShadowSocket(ShadowConfig config, InetAddress address, int port) throws IOException, NoSuchAlgorithmException {
        this(config);
        socket = new Socket(address, port);
        connectionStatus = true;
        handshake();
    }

    ShadowSocket(ShadowConfig config, InetAddress address, int port, InetAddress localAddr, int localPort) throws IOException, NoSuchAlgorithmException {
        this(config);
        socket = new Socket(address, port, localAddr, localPort);
        connectionStatus = true;
        handshake();
    }

    ShadowSocket(ShadowConfig config, Proxy proxy) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        this(config);
        socket = new Socket(proxy);
    }

    public void bind(SocketAddress bindpoint) throws IOException {
        socket.bind(bindpoint);
    }

    public void close() throws IOException {
        socket.close();
    }

    public void connect(SocketAddress endpoint) throws IOException {
        socket.connect(endpoint);
        if (connectionStatus) {
            throw new IOException();
        }
        connectionStatus = true;
        handshake();
    }

    public void connect(SocketAddress endpoint, int timeout) throws IOException {
        socket.connect(endpoint, timeout);
        if (connectionStatus) {
            throw new IOException();
        }
        handshake();
    }

    //TODO(i smell a recurring problem)
//    public SocketChannel getChannel() {
//        return new socket.channel;
//    }

//    public InetAddress getInetAddress() {
//        return socket.inetAddress;
//    }


    private void handshake() {
        sendSalt();
        receiveSalt();
    }

    private void sendSalt() {

    }

    private void receiveSalt() {

    }
}
