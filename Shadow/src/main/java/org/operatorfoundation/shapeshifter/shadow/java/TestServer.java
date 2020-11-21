package org.operatorfoundation.shapeshifter.shadow.java;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

import static org.operatorfoundation.shapeshifter.shadow.java.Utility.readNBytes;

public class TestServer implements Runnable {
    public TestServer() {

    }

    @Override
    public void run() {
        try {
            ServerSocket testServer = new ServerSocket(3333);
            Socket socket = testServer.accept();
            readNBytes(socket.getInputStream(), 2);
            socket.getOutputStream().write("Yo".getBytes());
            socket.getOutputStream().flush();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    public static void main(String args[]) {
        (new java.lang.Thread(new Thread())).start();
    }

}
