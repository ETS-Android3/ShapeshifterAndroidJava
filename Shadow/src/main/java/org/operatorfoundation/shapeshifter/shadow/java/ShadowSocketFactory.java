package org.operatorfoundation.shapeshifter.shadow.java;

import android.os.Build;

import androidx.annotation.RequiresApi;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Array;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.UUID;
import java.util.stream.Collectors;

import com.google.gson.Gson;

import javax.net.SocketFactory;

class JsonConfig {
    static class ServerConfig {
        String id;
        String server;
        int server_port;
        String password;
        String method;
    }

    static class ShadowJsonConfig {
        int version;
        ArrayList<ServerConfig> servers;
    }
}

public class ShadowSocketFactory extends SocketFactory {
    final ShadowConfig shadowConfig;
    final String shadowHost;
    final int shadowPort;


    public ShadowSocketFactory(ShadowConfig shadowConfig, String shadowHost, int shadowPort) {
        this.shadowConfig = shadowConfig;
        this.shadowHost = shadowHost;
        this.shadowPort = shadowPort;
    }

    @RequiresApi(api = Build.VERSION_CODES.N)
    public ShadowSocketFactory(URL url, UUID uuid) throws IOException {
        if (!url.getProtocol().equals("https")) {
            System.out.println("protocol must be https");
        }

        String jsonText;
        try (InputStream in = url.openStream())
        {
            BufferedReader reader = new BufferedReader(new InputStreamReader(in));
            jsonText = reader.lines().collect(Collectors.joining(System.lineSeparator()));
        }
        Gson gson = new Gson();
        JsonConfig.ShadowJsonConfig jsonConfig = gson.fromJson(jsonText, JsonConfig.ShadowJsonConfig.class);
        JsonConfig.ServerConfig serverConfig = jsonConfig.servers.get(0);

        if (UUID.fromString(serverConfig.id) != uuid) {
            System.out.println("uuid does not match");
        }

        ShadowConfig shadowConfig = new ShadowConfig(serverConfig.password, serverConfig.method);

        this.shadowConfig = shadowConfig;
        this.shadowHost = serverConfig.server;
        this.shadowPort = serverConfig.server_port;
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
        try {
            return new ShadowSocket(shadowConfig, shadowHost, shadowPort);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
            e.printStackTrace();
            throw new IOException();
        }
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException, UnknownHostException {
        try {
            return new ShadowSocket(shadowConfig, shadowHost, shadowPort);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
            e.printStackTrace();
            throw new IOException();
        }
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        try {
            return new ShadowSocket(shadowConfig, shadowHost, shadowPort);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
            e.printStackTrace();
            throw new IOException();
        }
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        try {
            return new ShadowSocket(shadowConfig, shadowHost, shadowPort);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
            e.printStackTrace();
            throw new IOException();
        }
    }

    @Override
    public Socket createSocket() throws IOException {
        try {
            return new OKHTTPShadowSocket(shadowConfig, shadowHost, shadowPort);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
            e.printStackTrace();
            throw new IOException();
        }
    }
}
