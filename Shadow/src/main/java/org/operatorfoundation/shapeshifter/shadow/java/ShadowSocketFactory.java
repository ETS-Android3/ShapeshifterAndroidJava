package org.operatorfoundation.shapeshifter.shadow.java;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.NoSuchAlgorithmException;

import javax.net.SocketFactory;

public class ShadowSocketFactory extends SocketFactory {
    final ShadowConfig shadowConfig;
    final String shadowHost;
    final int shadowPort;


    public ShadowSocketFactory(ShadowConfig shadowConfig, String shadowHost, int shadowPort) {
        this.shadowConfig = shadowConfig;
        this.shadowHost = shadowHost;
        this.shadowPort = shadowPort;
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
        try {
            return new ShadowSocket(shadowConfig, shadowHost, shadowPort);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new IOException();
        }
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException, UnknownHostException {
        try {
            return new ShadowSocket(shadowConfig, shadowHost, shadowPort);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new IOException();
        }
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        try {
            return new ShadowSocket(shadowConfig, shadowHost, shadowPort);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new IOException();
        }
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        try {
            return new ShadowSocket(shadowConfig, shadowHost, shadowPort);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new IOException();
        }
    }

    @Override
    public Socket createSocket() throws IOException {
        try {
            return new OKHTTPShadowSocket(shadowConfig, shadowHost, shadowPort);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new IOException();
        }
    }
}
