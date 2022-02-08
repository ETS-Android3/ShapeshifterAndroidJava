package org.operatorfoundation.shapeshifter.shadow.java;

import android.util.Log;

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
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

// This class implements client sockets (also called just "sockets").
public class ShadowSocket extends Socket {
    // Fields:
    Socket socket = new Socket();
    ShadowCipher encryptionCipher;
    ShadowCipher decryptionCipher;
    Boolean connectionStatus;
    private final ShadowConfig config;
    String host;
    int port;
    byte[] clientSalt;
    DarkStar darkStar;
    static Bloom bloom = new Bloom();
    Hole hole = new Hole();
    int holeTimeout = 30;

    public ShadowSocket(ShadowConfig config) {
        this.config = config;
    }

    // Constructors:
    // Creates a stream socket and connects it to the specified port number on the named host.
    public ShadowSocket(ShadowConfig config, String host, int port) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        this(config);
        this.host = host;
        this.port = port;

        // Create salt for encryptionCipher
        darkStar = new DarkStar(config, host, port);
        this.clientSalt = darkStar.createSalt();

        // Create an encryptionCipher
        socket = new Socket(host, port);
        connectionStatus = true;
         try {
             handshake();
         } catch(IOException error) {
             hole.startHole(holeTimeout, socket);
        }
        Log.i("init", "Encryption cipher created.");
    }

    // Creates a socket and connects it to the specified remote host on the specified remote port.
    public ShadowSocket(ShadowConfig config, String host, int port, InetAddress localAddr, int localPort) throws IOException {
        this(config);
        socket = new Socket(host, port, localAddr, localPort);
        connectionStatus = true;
        try {
            handshake();
        } catch(IOException error) {
            hole.startHole(holeTimeout, socket);
        }
    }

    // Creates a stream socket and connects it to the specified port number at the specified IP address.
    public ShadowSocket(ShadowConfig config, InetAddress address, int port) throws IOException {
        this(config);
        socket = new Socket(address, port);
        connectionStatus = true;
        try {
            handshake();
        } catch(IOException error) {
            hole.startHole(holeTimeout, socket);
        }
    }

    // Creates a socket and connects it to the specified remote address on the specified remote port.
    public ShadowSocket(ShadowConfig config, InetAddress address, int port, InetAddress localAddr, int localPort) throws IOException {
        this(config);
        socket = new Socket(address, port, localAddr, localPort);
        connectionStatus = true;
        try {
            handshake();
        } catch(IOException error) {
            hole.startHole(holeTimeout, socket);
        }
    }

    // Creates an unconnected socket, specifying the type of proxy, if any, that should be used regardless of any other settings.
    public ShadowSocket(ShadowConfig config, Proxy proxy) {
        this(config);
        socket = new Socket(proxy);
    }

    // Public functions:
    // Binds the socket to a local address.
    @Override
    public void bind(SocketAddress bindpoint) throws IOException {
        socket.bind(bindpoint);
    }

    // Closes this socket.
    @Override
    public void close() throws IOException {
        Log.i("close", "Socket closed.");
        socket.close();
    }

    // Connects this socket to the server and initiates the handshake.
    @Override
    public void connect(SocketAddress endpoint) throws IOException {
        if (connectionStatus) {
            Log.e("connect", "Already connected.");
            throw new IOException();
        }
        socket.connect(endpoint);
        connectionStatus = true;
        handshake();
        Log.i("connect", "Connect succeeded.");
    }

    // Connects this socket to the server with a specified timeout value and initiates the handshake.
    @Override
    public void connect(SocketAddress endpoint, int timeout) throws IOException {
        if (connectionStatus) {
            Log.e("connect", "Already connected.");
            throw new IOException();
        }
        socket.connect(endpoint, timeout);
        connectionStatus = true;
        handshake();
        Log.i("connect", "Connect succeeded.");
    }

    // Returns the unique SocketChannel object associated with this socket, if any.
    @Override
    public SocketChannel getChannel() {
        return socket.getChannel();
    }

    // Returns the address to which the socket is connected.
    @Override
    public InetAddress getInetAddress() {
        return socket.getInetAddress();
    }

    // Returns an input stream and the decryption cipher for this socket.
    @Override
    public InputStream getInputStream() throws IOException {
        ShadowCipher cipher = decryptionCipher;
        if (cipher != null) {
            Log.i("getInputStream", "Decryption cipher created.");
            return new ShadowInputStream(this, socket.getInputStream(), cipher);
        }
        Log.e("getInputStream", "Decryption cipher was not created.");
        throw new IOException();
    }

    // Tests if SO_KEEPALIVE is enabled.
    @Override
    public boolean getKeepAlive() {
        return false;
    }

    // Gets the local address to which the socket is bound.
    @Override
    public InetAddress getLocalAddress() {
        return socket.getLocalAddress();
    }

    // Returns the local port number to which this socket is bound.
    @Override
    public int getLocalPort() {
        return socket.getLocalPort();
    }

    // Returns the address of the endpoint this socket is bound to.
    @Override
    public SocketAddress getLocalSocketAddress() {
        return socket.getLocalSocketAddress();
    }

    // Tests if SO_OOBINLINE is enabled.
    @Override
    public boolean getOOBInline() {
        return false;
    }

    // Returns an output stream and the encryption cipher for this socket.
    @Override
    public OutputStream getOutputStream() throws IOException {
        return new ShadowOutputStream(socket.getOutputStream(), encryptionCipher);
    }

    // Returns the remote port number to which this socket is connected.
    @Override
    public int getPort() {
        return socket.getPort();
    }

    // Gets the value of the SO_RCVBUF option for this Socket, that is the buffer size used by the platform for input on this Socket.
    @Override
    public int getReceiveBufferSize() throws SocketException {
        return socket.getReceiveBufferSize();
    }

    // Returns the address of the endpoint this socket is connected to, or null if it is unconnected.
    @Override
    public SocketAddress getRemoteSocketAddress() {
        return socket.getRemoteSocketAddress();
    }

    // Tests if SO_REUSEADDR is enabled.
    @Override
    public boolean getReuseAddress() {
        return false;
    }

    // Get value of the SO_SNDBUF option for this Socket, that is the buffer size used by the platform for output on this Socket.
    @Override
    public int getSendBufferSize() throws SocketException {
        return socket.getSendBufferSize();
    }

    // Returns setting for SO_LINGER. -1 implies that the option is disabled.
    @Override
    public int getSoLinger() {
        return -1;
    }

    // Returns setting for SO_TIMEOUT. 0 returns implies that the option is disabled (i.e., timeout of infinity).
    @Override
    public int getSoTimeout() {
        return 0;
    }

    // Tests if TCP_NODELAY is enabled.
    @Override
    public boolean getTcpNoDelay() {
        return false;
    }

    // Gets traffic class or type-of-service in the IP header for packets sent from this Socket.
    @Override
    public int getTrafficClass() throws SocketException {
        throw new SocketException();
    }

    // Returns the binding state of the socket.
    @Override
    public boolean isBound() {
        return socket.isBound();
    }

    // Returns the closed state of the socket.
    @Override
    public boolean isClosed() {
        return socket.isClosed();
    }

    // Returns the connection state of the socket.
    @Override
    public boolean isConnected() {
        return socket.isConnected();
    }

    // Returns whether the read-half of the socket connection is closed.
    @Override
    public boolean isInputShutdown() {
        return socket.isInputShutdown();
    }

    // Returns whether the write-half of the socket connection is closed.
    @Override
    public boolean isOutputShutdown() {
        return socket.isOutputShutdown();
    }

    // Send one byte of urgent data on the socket.
    @Override
    public void sendUrgentData(int data) {
    }

    // Sets the SO_RCVBUF option to the specified value for this Socket.
    @Override
    public void setReceiveBufferSize(int size) throws SocketException {
        socket.setSendBufferSize(size);
    }

    // Sets the SO_SNDBUF option to the specified value for this Socket.
    @Override
    public void setSendBufferSize(int size) throws SocketException {
        socket.setSendBufferSize(size);
    }

    // Enable/disable SO_TIMEOUT with the specified timeout, in milliseconds.
    @Override
    public void setSoTimeout(int timeout) {
    }

    // Sets traffic class or type-of-service octet in the IP header for packets sent from this Socket.
    @Override
    public void setTrafficClass(int tc) throws SocketException {
        throw new SocketException();
    }

    // Private functions:
    // Exchanges the salt.
    private void handshake() throws IOException {
        sendSalt();
        try {
            receiveSalt();
            Log.i("handshake", "handshake completed");
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    // Sends the salt through the output stream.
    private void sendSalt() throws IOException {
        socket.getOutputStream().write(this.clientSalt);
        Log.i("sendSalt", "Salt sent.");
    }

    // Receives the salt through the input stream.
    private void receiveSalt() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, InvalidKeyException {
        int saltSize = ShadowCipher.determineSaltSize();
        byte[] result = Utility.readNBytes(socket.getInputStream(), saltSize);
        if (result != null && result.length == this.clientSalt.length) {
            if (bloom.checkBloom(result)) {
                Log.e("receiveSalt", "duplicate salt found");
                throw new IOException();
            }
            decryptionCipher = darkStar.makeCipher(true, result);
            encryptionCipher = darkStar.makeCipher(false, result);
            Log.i("receiveSalt", "Salt received.");
        } else {
            Log.e("receiveSalt", "Salt was not received.");
            throw new IOException();
        }
    }

    static void saveBloom(String fileName) throws IOException {
        bloom.save(fileName);
    }
    static void loadBloom(String fileName) throws IOException {
        bloom.load(fileName);
    }
}
