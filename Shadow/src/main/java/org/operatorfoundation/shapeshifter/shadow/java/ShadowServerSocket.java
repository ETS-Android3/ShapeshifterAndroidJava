package org.operatorfoundation.shapeshifter.shadow.java;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.channels.ServerSocketChannel;

// This class implements server sockets. A server socket waits for requests to come in over the network.
public class ShadowServerSocket {

    // Fields:
    static ShadowConfig config;
    static ServerSocket serverSocket;

    // It performs some operation based on that request, and then possibly returns a result to the requester.
    public ShadowServerSocket(ShadowConfig config) {

    }

    // Constructors:
    // Creates a server socket, bound to the specified port.
    ShadowServerSocket(ShadowConfig config, int port) throws IOException {
        this(config);
        serverSocket = new ServerSocket(port);
    }

    // Creates a server socket and binds it to the specified local port number, with the specified backlog.
    ShadowServerSocket(ShadowConfig config, int port, int backlog) throws IOException {
        this(config);
        serverSocket = new ServerSocket(port, backlog);
    }

    // Create a server with the specified port, listen backlog, and local IP address to bind to.
    ShadowServerSocket(ShadowConfig config, int port, int backlog, InetAddress bindAddr) throws IOException {
        this(config);
        serverSocket = new ServerSocket(port, backlog, bindAddr);
    }

    // Public methods:
    // Listens for a connection to be made to this socket and accepts it.
    public Socket accept() throws IOException {
        return serverSocket.accept();
    }

    // Binds the ServerSocket to a specific address (IP address and port number).
    public void bind(SocketAddress endpoint) throws IOException {
        serverSocket.bind(endpoint);
    }

    // Binds the ServerSocket to a specific address (IP address and port number).
    public void bind(SocketAddress endpoint, int backlog) throws IOException {
        serverSocket.bind(endpoint, backlog);
    }

    // Closes this socket.
    public void close() throws IOException {
        serverSocket.close();
    }

    // Returns the unique ServerSocketChannel object associated with this socket, if any.
    public ServerSocketChannel getChannel() {
        return serverSocket.getChannel();
    }

    // Returns the local address of this server socket.
    public InetAddress getInetAddress() {
        return serverSocket.getInetAddress();
    }

    // Returns the port number on which this socket is listening.
    public int getLocalPort() {
        return serverSocket.getLocalPort();
    }

    // Returns the address of the endpoint this socket is bound to.
    public SocketAddress getLocalSocketAddress() {
        return serverSocket.getLocalSocketAddress();
    }

    // Gets the value of the SO_RCVBUF option for this ServerSocket, that is the proposed buffer size that will be used for Sockets accepted from this ServerSocket.
    public int getReceiveBufferSize() throws SocketException {
        return serverSocket.getReceiveBufferSize();
    }

    // Tests if SO_REUSEADDR is enabled.
    public Boolean getReuseAddress() throws SocketException {
        return serverSocket.getReuseAddress();
    }

    // Retrieve setting for SO_TIMEOUT. 0 returns implies that the option is disabled (i.e., timeout of infinity).
    public int getSoTimeout() throws IOException {
        return serverSocket.getSoTimeout();
    }

    // Returns the binding state of the ServerSocket.
    public Boolean isBound() {
        return serverSocket.isBound();
    }

    // Returns the closed state of the ServerSocket.
    public Boolean isClosed() {
        return serverSocket.isClosed();
    }

    // Sets performance preferences for this ServerSocket.
    public void setPerformancePreferences(int connectionTime, int latency, int bandwidth) {
    }

    // Sets a default proposed value for the SO_RCVBUF option for sockets accepted from this ServerSocket.
    public void setReceiveBufferSize(int size) throws SocketException {
        serverSocket.setReceiveBufferSize(size);
    }

    // Enable/disable the SO_REUSEADDR socket option.
    public void setReuseAddress(Boolean on) {
    }

    // Enable/disable SO_TIMEOUT with the specified timeout, in milliseconds.
    public void setSoTimeout(int timeout) {
    }

}
