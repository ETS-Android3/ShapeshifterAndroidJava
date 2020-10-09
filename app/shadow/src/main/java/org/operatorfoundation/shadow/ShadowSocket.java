package org.operatorfoundation.shadow;


import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Proxy;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.channels.SocketChannel;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.NoSuchPaddingException;

// This class implements client sockets (also called just "sockets").
public class ShadowSocket {
    // Fields:
    static Socket socket = new Socket();
    static ShadowCipher encryptionCipher;
    static ShadowCipher decryptionCipher;
    static Boolean connectionStatus;

    ShadowSocket(ShadowConfig config) {
    }

    // Constructors:
    // Creates a stream socket and connects it to the specified port number on the named host.
    ShadowSocket(ShadowConfig config, String host, int port) throws IOException, NoSuchAlgorithmException {
        this(config);
        socket = new Socket(host, port);
        connectionStatus = true;
        handshake();
    }

    // Creates a socket and connects it to the specified remote host on the specified remote port.
    ShadowSocket(ShadowConfig config, String host, int port, InetAddress localAddr, int localPort) throws IOException, NoSuchAlgorithmException {
        this(config);
        socket = new Socket(host, port, localAddr, localPort);
        connectionStatus = true;
        handshake();
    }

    // Creates a stream socket and connects it to the specified port number at the specified IP address.
    ShadowSocket(ShadowConfig config, InetAddress address, int port) throws IOException, NoSuchAlgorithmException {
        this(config);
        socket = new Socket(address, port);
        connectionStatus = true;
        handshake();
    }

    // Creates a socket and connects it to the specified remote address on the specified remote port.
    ShadowSocket(ShadowConfig config, InetAddress address, int port, InetAddress localAddr, int localPort) throws IOException, NoSuchAlgorithmException {
        this(config);
        socket = new Socket(address, port, localAddr, localPort);
        connectionStatus = true;
        handshake();
    }

    // Creates an unconnected socket, specifying the type of proxy, if any, that should be used regardless of any other settings.
    ShadowSocket(ShadowConfig config, Proxy proxy) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        this(config);
        socket = new Socket(proxy);
    }

    // A socket is an endpoint for communication between two machines.
    public Socket main(final ShadowConfig config) throws NoSuchAlgorithmException {
        return new Socket() {
            // Init block:
            {
                // Create salt for encryptionCipher
                byte[] salt = ShadowCipher.createSalt(config);
                // Create an encryptionCipher
                encryptionCipher = new ShadowCipher(config, salt);
            }


            // Public functions:
            // Binds the socket to a local address.
            public void bind(SocketAddress bindpoint) throws IOException {
                socket.bind(bindpoint);
            }

            // Closes this socket.
            public void close() throws IOException {
                socket.close();
            }

            // Connects this socket to the server and initiates the handshake.
            public void connect(SocketAddress endpoint) throws IOException {
                socket.connect(endpoint);
                if (connectionStatus) {
                    throw new IOException();
                }
                connectionStatus = true;
                handshake();
            }

            // Connects this socket to the server with a specified timeout value and initiates the handshake.
            public void connect(SocketAddress endpoint, int timeout) throws IOException {
                socket.connect(endpoint, timeout);
                if (connectionStatus) {
                    throw new IOException();
                }
                handshake();
            }

            //TODO(some methods dont have the variables i.e: socket.channel like they do in kotlin)

            // Returns the unique SocketChannel object associated with this socket, if any.
            public SocketChannel getChannel() {
                return socket.getChannel();
            }

            // Returns the address to which the socket is connected.
            public InetAddress getInetAddress() {
                return socket.getInetAddress();
            }

            // Returns an input stream and the decryption cipher for this socket.
//            public InputStream getInputStream() throws IOException {
//                ShadowCipher cipher = decryptionCipher;
//                if (cipher != null) {
//                    return new ShadowInputStream(socket.getInputStream(), cipher);
//                }
//                throw new IOException();
//            }

            // Tests if SO_KEEPALIVE is enabled.
            public boolean getKeepAlive() {
                return false;
            }

            // Gets the local address to which the socket is bound.
            public InetAddress getLocalAddress() {
                return socket.getLocalAddress();
            }

            // Returns the local port number to which this socket is bound.
            public int getLocalPort() {
                return socket.getLocalPort();
            }

            // Returns the address of the endpoint this socket is bound to.
            public SocketAddress getLocalSocketAddress() {
                return socket.getLocalSocketAddress();
            }

            // Tests if SO_OOBINLINE is enabled.
            public boolean getOOBInline() {
                return false;
            }

            // Returns an output stream and the encryption cipher for this socket.
//            public OutputStream getOutputStream() throws IOException {
//                return new ShadowOutputStream(socket.getOutputStream(), encryptionCipher);
//            }

            // Returns the remote port number to which this socket is connected.
            public int getPort() {
                return socket.getPort();
            }

            // Gets the value of the SO_RCVBUF option for this Socket, that is the buffer size used by the platform for input on this Socket.
            public int getReceiveBufferSize() throws SocketException {
                return socket.getReceiveBufferSize();
            }

            // Returns the address of the endpoint this socket is connected to, or null if it is unconnected.
            public SocketAddress getRemoteSocketAddress() {
                return socket.getRemoteSocketAddress();
            }

            // Tests if SO_REUSEADDR is enabled.
            public boolean getReuseAddress() {
                return false;
            }

            // Get value of the SO_SNDBUF option for this Socket, that is the buffer size used by the platform for output on this Socket.
            public int getSendBufferSize() throws SocketException {
                return socket.getSendBufferSize();
            }

            // Returns setting for SO_LINGER. -1 implies that the option is disabled.
            public int getSoLinger() {
                return -1;
            }

            // Returns setting for SO_TIMEOUT. 0 returns implies that the option is disabled (i.e., timeout of infinity).
            public int getSoTimeout() {
                return 0;
            }

            // Tests if TCP_NODELAY is enabled.
            public boolean getTcpNoDelay() {
                return false;
            }

            // Gets traffic class or type-of-service in the IP header for packets sent from this Socket.
            public int getTrafficClass() throws SocketException {
                throw new SocketException();
            }

            // Returns the binding state of the socket.
            public boolean isBound() {
                return socket.isBound();
            }

            // Returns the closed state of the socket.
            public boolean isClosed() {
                return socket.isClosed();
            }

            // Returns the connection state of the socket.
            public boolean isConnected() {
                return socket.isConnected();
            }

            // Returns whether the read-half of the socket connection is closed.
            public boolean isInputShutdown() {
                return socket.isInputShutdown();
            }

            // Returns whether the write-half of the socket connection is closed.
            public boolean isOutputShutdown() {
                return socket.isOutputShutdown();
            }

            // Send one byte of urgent data on the socket.
            public void sendUrgentData(int data) {
            }

            // Sets the SO_RCVBUF option to the specified value for this Socket.
            public void setReceiveBufferSize(int size) throws SocketException {
                socket.setSendBufferSize(size);
            }

            // Sets the SO_SNDBUF option to the specified value for this Socket.
            public void setSendBufferSize(int size) throws SocketException {
                socket.setSendBufferSize(size);
            }

            // Enable/disable SO_TIMEOUT with the specified timeout, in milliseconds.
            public void setSoTimeout(int timeout) {
            }

            // Sets traffic class or type-of-service octet in the IP header for packets sent from this Socket.
            public void setTrafficClass(int tc) throws SocketException {
                throw new SocketException();
            }

            // Converts this socket to a String.
            @Override
            public String toString() {
                return "ShadowSocket[" + "password = " + config.password + ", cipherName = " + config.cipherName + "]";
            }
        };
    }

    // Private functions:
    // Exchanges the salt.
    private void handshake() throws IOException {
        sendSalt();
        try {
            receiveSalt();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    // Sends the salt through the output stream.
    private void sendSalt() {
//        socket.outputStream.write(encryptionCipher.salt);
    }

    // Receives the salt through the input stream.
    private void receiveSalt() throws NoSuchAlgorithmException, IOException {
//        byte[] result = Utility.readNBytes(socket.inputStream, ShadowCipher.saltSize);
//        if (result.length == ShadowCipher.salt.length) {
//            decryptionCipher = new ShadowCipher(config, result);
//        } else {
//            throw new IOException();
//        }
    }
}
