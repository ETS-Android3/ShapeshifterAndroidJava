//package org.operatorfoundation.shadow;
//
//
//import java.io.IOException;
//import java.net.InetAddress;
//import java.net.Proxy;
//import java.net.Socket;
//import java.net.SocketAddress;
//import java.net.SocketException;
//import java.security.InvalidKeyException;
//import java.security.NoSuchAlgorithmException;
//
//import javax.crypto.NoSuchPaddingException;
//
//import static org.operatorfoundation.shadow.ShadowCipher.config;
//
//// This class implements client sockets (also called just "sockets").
//public class ShadowSocket {
//    // Fields:
//    static Socket socket = new Socket();
//    static ShadowCipher encryptionCipher;
//    static ShadowCipher decryptionCipher;
//    static Boolean connectionStatus;
//
//    // A socket is an endpoint for communication between two machines.
//    public ShadowSocket(ShadowConfig config) throws NoSuchAlgorithmException {
//        // Init block:
//        {
//            // Create salt for encryptionCipher
//            byte[] salt = ShadowCipher.createSalt(config);
//            // Create an encryptionCipher
//            encryptionCipher = new ShadowCipher(config, salt);
//        }
//    }
//
//    // Constructors:
//    // Creates a stream socket and connects it to the specified port number on the named host.
//    ShadowSocket(ShadowConfig config, String host, int port) throws IOException, NoSuchAlgorithmException {
//        this(config);
//        socket = new Socket(host, port);
//        connectionStatus = true;
//        handshake();
//    }
//
//    // Creates a socket and connects it to the specified remote host on the specified remote port.
//    ShadowSocket(ShadowConfig config, String host, int port, InetAddress localAddr, int localPort) throws IOException, NoSuchAlgorithmException {
//        this(config);
//        socket = new Socket(host, port, localAddr, localPort);
//        connectionStatus = true;
//        handshake();
//    }
//
//    // Creates a stream socket and connects it to the specified port number at the specified IP address.
//    ShadowSocket(ShadowConfig config, InetAddress address, int port) throws IOException, NoSuchAlgorithmException {
//        this(config);
//        socket = new Socket(address, port);
//        connectionStatus = true;
//        handshake();
//    }
//
//    // Creates a socket and connects it to the specified remote address on the specified remote port.
//    ShadowSocket(ShadowConfig config, InetAddress address, int port, InetAddress localAddr, int localPort) throws IOException, NoSuchAlgorithmException {
//        this(config);
//        socket = new Socket(address, port, localAddr, localPort);
//        connectionStatus = true;
//        handshake();
//    }
//
//    // Creates an unconnected socket, specifying the type of proxy, if any, that should be used regardless of any other settings.
//    ShadowSocket(ShadowConfig config, Proxy proxy) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
//        this(config);
//        socket = new Socket(proxy);
//    }
//
//    // Public functions:
//    // Binds the socket to a local address.
//    public void bind(SocketAddress bindpoint) throws IOException {
//        socket.bind(bindpoint);
//    }
//
//    // Closes this socket.
//    public void close() throws IOException {
//        socket.close();
//    }
//
//    // Connects this socket to the server and initiates the handshake.
//    public void connect(SocketAddress endpoint) throws IOException, NoSuchAlgorithmException {
//        socket.connect(endpoint);
//        if (connectionStatus) {
//            throw new IOException();
//        }
//        connectionStatus = true;
//        handshake();
//    }
//
//    // Connects this socket to the server with a specified timeout value and initiates the handshake.
//    public void connect(SocketAddress endpoint, int timeout) throws IOException, NoSuchAlgorithmException {
//        socket.connect(endpoint, timeout);
//        if (connectionStatus) {
//            throw new IOException();
//        }
//        handshake();
//    }
//
//    //TODO(i smell a recurring problem starting below)
//
//    // Returns the unique SocketChannel object associated with this socket, if any.
////    public SocketChannel getChannel() {
////        return new socket.channel;
////    }
//
//    // Returns the address to which the socket is connected.
////    public InetAddress getInetAddress() {
////        return socket.inetAddress;
////    }
//
//    // Returns an input stream and the decryption cipher for this socket.
////    public InputStream getInputStream() throws Throwable {
////        ShadowCipher cipher = decryptionCipher;
////        if (cipher != null) {
////            return ShadowInputStream(socket.inputStream, cipher);
////        }
////        throw new IOException();
////    }
//
//    // Tests if SO_KEEPALIVE is enabled.
//    public Boolean getKeepAlive() {
//        return false;
//    }
//
//    // Gets the local address to which the socket is bound.
////    public InetAddress getLocalAddress() {
////        return socket.inetAddress;
////    }
//
//    // Returns the local port number to which this socket is bound.
////    public int getLocalPort() {
////        return socket.localPort;
////    }
//
//    // Returns the address of the endpoint this socket is bound to.
////    public SocketAddress getLocalSocketAddress() {
////        return socket.localSocketAddress;
////    }
//
//    // Tests if SO_OOBINLINE is enabled.
//    public Boolean getOOBInline() {
//        return false;
//    }
//
//    // Returns an output stream and the encryption cipher for this socket.
////    public OutputStream getOutputStream() {
////        return ShadowOutputStream(socket.outputStream, encryptionCipher);
////    }
//
//    // Returns the remote port number to which this socket is connected.
////    public int getPort() {
////        return socket.port;
////    }
//
//    // Gets the value of the SO_RCVBUF option for this Socket, that is the buffer size used by the platform for input on this Socket.
////    public int getReceiveBufferSize() {
////        return socket.receiveBufferSize;
////    }
//
//    // Returns the address of the endpoint this socket is connected to, or null if it is unconnected.
////    public SocketAddress getRemoteSocketAddress() {
////        return socket.remoteSocketAddress;
////    }
//
//    // Tests if SO_REUSEADDR is enabled.
//    public Boolean getReuseAddress() {
//        return false;
//    }
//
//    // Get value of the SO_SNDBUF option for this Socket, that is the buffer size used by the platform for output on this Socket.
////    public int getSendBufferSize() {
////        return socket.sendBufferSize;
////    }
//
//    // Returns setting for SO_LINGER. -1 implies that the option is disabled.
//    public int getSoLinger() {
//        return -1;
//    }
//
//    // Returns setting for SO_TIMEOUT. 0 returns implies that the option is disabled (i.e., timeout of infinity).
//    public int getSoTimeout() {
//        return 0;
//    }
//
//    // Tests if TCP_NODELAY is enabled.
//    public Boolean getTcpNoDelay() {
//        return false;
//    }
//
//    // Gets traffic class or type-of-service in the IP header for packets sent from this Socket.
//    public int getTrafficClass() throws SocketException {
//        throw new SocketException();
//    }
//
//    // Returns the binding state of the socket.
////    public Boolean isBound() {
////        return socket.isBound;
////    }
//
//    // Returns the closed state of the socket.
////    public Boolean isClosed() {
////        return socket.isClosed;
////    }
//
//    // Returns the connection state of the socket.
////    public Boolean isConnected() {
////        return socket.isConnected;
////    }
//
//    // Returns whether the read-half of the socket connection is closed.
////    public Boolean isInputShutdown() {
////        return socket.isInputShutdown;
////    }
//
//    // Returns whether the write-half of the socket connection is closed.
////    public Boolean isOutputShutdown() {
////        return socket.isOutputShutdown;
////    }
//
//    // Send one byte of urgent data on the socket.
//    public void sendUrgentData(int data) {
//    }
//
//    // Enable/disable SO_KEEPALIVE.
//    public void setKeepAlive(Boolean on) {
//    }
//
//    // Enable/disable SO_OOBINLINE (receipt of TCP urgent data) By default, this option is disabled and TCP urgent data received on a socket is silently discarded.
//    public void setOOBInline(Boolean on) {
//    }
//
//    // Sets performance preferences for this socket.
//    public void setPerformancePreference(int connectionTime, int latency, int bandwidth) {
//    }
//
//    // Sets the SO_RCVBUF option to the specified value for this Socket.
////    public void setReceiveBufferSize(int size) {
////        socket.sendBufferSize = size;
////    }
//
//    // Enable/disable the SO_REUSEADDR socket option.
//    public void setReuseAddress(Boolean on) {
//    }
//
//    // Sets the SO_SNDBUF option to the specified value for this Socket.
////    public void setSendBufferSize(int size) {
////        socket.sendBufferSize = size;
////    }
//
//    // Enable/disable SO_LINGER with the specified linger time in seconds.
//    public void setSoLinger(Boolean on, int linger) {
//    }
//
//    // Enable/disable SO_TIMEOUT with the specified timeout, in milliseconds.
//    public void setSoTimeout(int timeout) {
//    }
//
//    // Enable/disable TCP_NODELAY (disable/enable Nagle's algorithm).
//    public void setTcpNoDelay(Boolean on) {
//    }
//
//    // Sets traffic class or type-of-service octet in the IP header for packets sent from this Socket.
//    public void setTrafficClass(int tc) throws SocketException {
//        throw new SocketException();
//    }
//
//    // Places the input stream for this socket at "end of stream".
//    public void shutDownInput() throws IOException {
//        socket.shutdownInput();
//    }
//
//    // Disables the output stream for this socket.
//    public void shutDownOutput() throws IOException {
//        socket.shutdownOutput();
//    }
//
//    // Converts this socket to a String.
//    public String toString() {
//        return "ShadowSocket[" + "password = " + config.password + ", cipherName = " + config.cipherName + "]";
//    }
//
//    // Private functions:
//    // Exchanges the salt.
//    private void handshake() throws IOException, NoSuchAlgorithmException {
//        sendSalt();
//        receiveSalt();
//    }
//
//    // Sends the salt through the output stream.
//    private void sendSalt() {
//        //socket.outputStream.write(encryptionCipher.salt);
//    }
//
//    // Receives the salt through the input stream.
//    private void receiveSalt() throws NoSuchAlgorithmException, IOException {
////        byte[] result = Utility.readNBytes(socket.inputStream, ShadowCipher.saltSize);
////        if (result.length == ShadowCipher.salt.length) {
////            decryptionCipher = new ShadowCipher(config, result);
////        } else {
////            throw new IOException();
////        }
//    }
//}
//
