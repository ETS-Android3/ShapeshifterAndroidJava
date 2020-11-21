package org.operatorfoundation.shapeshifter.shadow.java;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketAddress;
import java.net.SocketOption;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.MembershipKey;
import java.nio.channels.spi.SelectorProvider;
import java.util.Set;

public class ShadowDatagramChannel {

    public DatagramChannel ShadowDatagramChannel(SelectorProvider provider) {
        return new DatagramChannel(provider) {
            @Override
            protected void implCloseSelectableChannel() throws IOException {

            }

            @Override
            protected void implConfigureBlocking(boolean block) throws IOException {

            }

            @Override
            public MembershipKey join(InetAddress group, NetworkInterface interf) throws IOException {
                return null;
            }

            @Override
            public MembershipKey join(InetAddress group, NetworkInterface interf, InetAddress source) throws IOException {
                return null;
            }

            @Override
            public DatagramChannel bind(SocketAddress local) throws IOException {
                return null;
            }

            @Override
            public <T> DatagramChannel setOption(SocketOption<T> name, T value) throws IOException {
                return null;
            }

            @Override
            public <T> T getOption(SocketOption<T> name) throws IOException {
                return null;
            }

            @Override
            public Set<SocketOption<?>> supportedOptions() {
                return null;
            }

            @Override
            public DatagramSocket socket() {
                return null;
            }

            @Override
            public boolean isConnected() {
                return false;
            }

            @Override
            public DatagramChannel connect(SocketAddress remote) throws IOException {
                return null;
            }

            @Override
            public DatagramChannel disconnect() throws IOException {
                return null;
            }

            @Override
            public SocketAddress getRemoteAddress() throws IOException {
                return null;
            }

            @Override
            public SocketAddress receive(ByteBuffer dst) throws IOException {
                return null;
            }

            @Override
            public int send(ByteBuffer src, SocketAddress target) throws IOException {
                return 0;
            }

            @Override
            public int read(ByteBuffer dst) throws IOException {
                return 0;
            }

            @Override
            public long read(ByteBuffer[] dsts, int offset, int length) throws IOException {
                return 0;
            }

            @Override
            public int write(ByteBuffer src) throws IOException {
                return 0;
            }

            @Override
            public long write(ByteBuffer[] srcs, int offset, int length) throws IOException {
                return 0;
            }

            @Override
            public SocketAddress getLocalAddress() throws IOException {
                return null;
            }
        };
    }
}
