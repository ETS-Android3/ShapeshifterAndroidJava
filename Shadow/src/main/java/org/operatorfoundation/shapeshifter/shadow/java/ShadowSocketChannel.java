package org.operatorfoundation.shapeshifter.shadow.java;

import java.io.IOException;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketOption;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.nio.channels.spi.SelectorProvider;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

public class ShadowSocketChannel {

    public boolean connectionStatus = false;
    public SocketChannel socketChannel = SocketChannel.open();
    public ShadowCipher encryptionCipher;
    public ShadowCipher decryptionCipher;

    public ShadowSocketChannel(ShadowCipher encryptionCipher, ShadowCipher decryptionCipher) throws IOException {
        this.encryptionCipher = encryptionCipher;
        this.decryptionCipher = decryptionCipher;
    }

    public SocketChannel main(SelectorProvider selectorProvider, final ShadowConfig config) throws NoSuchAlgorithmException {
        return new SocketChannel(selectorProvider) {
            // Init block:
            {
                // Create an encryptionCipher
                encryptionCipher = ShadowCipher.makeShadowCipher(config);
            }

            @Override
            public SocketChannel bind(SocketAddress local) throws IOException {
                return socketChannel.bind(local);
            }

            @Override
            public boolean connect(SocketAddress remote) throws IOException {
                socketChannel = open(remote);
                if (connectionStatus) {
                    return false;
                }
                connectionStatus = true;
                try {
                    handshake();
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }
                return true;
            }

            @Override
            public boolean finishConnect() throws IOException {
                return connectionStatus;
            }

            @Override
            public SocketAddress getLocalAddress() throws IOException {
                return socketChannel.getLocalAddress();
            }

            @Override
            public <T> T getOption(SocketOption<T> name) throws IOException {
                throw new UnsupportedOperationException();
            }

            @Override
            public SocketAddress getRemoteAddress() throws IOException {
                return socketChannel.getRemoteAddress();
            }

            @Override
            protected void implCloseSelectableChannel() throws IOException {
            }

            @Override
            protected void implConfigureBlocking(boolean block) throws IOException {
            }

            @Override
            public boolean isConnected() {
                return connectionStatus;
            }

            @Override
            public boolean isConnectionPending() {
                boolean isConnectionPending = false;
                try {
                    isConnectionPending = finishConnect();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                return isConnectionPending;
            }

            @Override
            public int read(ByteBuffer dst) throws IOException {
                byte[] buffer = new byte[0];
                byte[] data = new byte[(dst.capacity())];
                if (data.length == 0) {
                    return 0;
                }

                // puts bytes in a buffer.
                if (data.length <= buffer.length) {
                    int resultSize = Integer.min(data.length, buffer.length);
                    System.arraycopy(buffer, 0, data, 0, resultSize);
                    buffer = Arrays.copyOfRange(buffer, resultSize + 1, buffer.length - 1);

                    return resultSize;
                }

                // get encrypted length.
                int lengthDataSize = ShadowCipher.lengthWithTagSize;

                // read bytes up to the size of encrypted lengthSize into a byte buffer.
                ByteBuffer encryptedLengthData = Utility.readNBytes(socketChannel, lengthDataSize);

                // decrypt encrypted length to find out payload length.
                byte[] lengthData = new byte[0];
                try {
                    lengthData = decryptionCipher.decrypt(new byte[encryptedLengthData.capacity()]);
                } catch (InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
                    e.printStackTrace();
                }

                // change lengthData from  BigEndian representation to int length.
                byte leftByte = lengthData[0];
                byte rightByte = lengthData[1];
                int payloadLength = ((int)leftByte * 256) + (int)rightByte;

                // read and decrypt payload with the resulting length.
                ByteBuffer encryptedPayload = Utility.readNBytes(socketChannel, payloadLength + ShadowCipher.tagSize);
                byte[] payload = new byte[0];
                try {
                    payload = decryptionCipher.decrypt(new byte[encryptedPayload.capacity()]);
                } catch (InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException e) {
                    e.printStackTrace();
                }

                // put payload into buffer
                buffer = Utility.plusEqualsByteArray(buffer, payload);
                int resultSize = Integer.min(data.length, buffer.length);

                // take bytes out of buffer
                System.arraycopy(buffer, 0, buffer, resultSize + 1, buffer.length);

                return resultSize;
            }

            @Override
            public long read(ByteBuffer[] dsts, int offset, int length) throws IOException {
//                dsts.get(offset).remaining();
//                dsts.get(offset + 1).remaining();
//                return dsts.get(offset + length - 1).remaining();
                return 0;
            }

            @Override
            public <T> SocketChannel setOption(SocketOption<T> name, T value) throws IOException {
                return socketChannel.setOption(name, value);
            }

            @Override
            public SocketChannel shutdownInput() throws IOException {
                return socketChannel.shutdownInput();
            }

            @Override
            public SocketChannel shutdownOutput() throws IOException {
                return socketChannel.shutdownOutput();
            }

            @Override
            public Socket socket() {
                return socket();
            }

            @Override
            public Set<SocketOption<?>> supportedOptions() {
                return null;
            }

            @Override
            public int write(ByteBuffer src) throws IOException {
                byte[] buffer = new byte[0];
                byte[] data = new byte[src.capacity()];
                if (data.length == 0) {
                    return 0;
                }

                // put into buffer.
                buffer = Utility.plusEqualsByteArray(buffer, data);

                // keep writing until the buffer is empty in case user exceeds maximum.
                while (buffer.length > 0) {
                    int numBytesToSend = Integer.min(ShadowCipher.maxPayloadSize, buffer.length);

                     //make a copy of the buffer
                    byte[] bytesToSend = new byte[numBytesToSend];

                     //take bytes out of buffer.
                    System.arraycopy(buffer, 0, bytesToSend, 0, numBytesToSend);

                    byte[] cipherText = new byte[0];
                    try {
                        cipherText = encryptionCipher.pack(bytesToSend);
                    } catch (InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
                        e.printStackTrace();
                    }

                    socketChannel.write(ByteBuffer.wrap(cipherText));
                }
                return src.remaining();
            }

            @Override
            public long write(ByteBuffer[] srcs, int offset, int length) throws IOException {
//                srcs.get(offset).remaining();
//                srcs.get(offset + 1).remaining();
//                return srcs.get(offset + length - 1).remaining();
                return 0;
            }
        };
    }

    public void handshake() throws IOException, NoSuchAlgorithmException {
        sendSalt();
        receiveSalt();
    }

    public void sendSalt() throws IOException {
        ByteBuffer buffer = ByteBuffer.wrap(encryptionCipher.salt);
        socketChannel.write(buffer);
    }

    public void receiveSalt() throws IOException, NoSuchAlgorithmException {
        SocketChannel channel = socketChannel;
        int saltSize = ShadowCipher.determineSaltSize(encryptionCipher.config);
        ByteBuffer result = Utility.readNBytes(channel, saltSize);
        if (result.position() == encryptionCipher.salt.length) {
            decryptionCipher = ShadowCipher.makeShadowCipherWithSalt(encryptionCipher.config, result.array());
        } else {
            throw new IOException();
        }
    }
}
