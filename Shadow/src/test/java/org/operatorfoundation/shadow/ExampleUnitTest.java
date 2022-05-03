package org.operatorfoundation.shadow;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.operatorfoundation.shapeshifter.shadow.java.DarkStar.bytesToHex;
import static org.operatorfoundation.shapeshifter.shadow.java.DarkStar.bytesToPublicKey;
import static org.operatorfoundation.shapeshifter.shadow.java.DarkStar.generateECKeys;
import static org.operatorfoundation.shapeshifter.shadow.java.DarkStar.hexToBytes;

import android.util.Log;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.junit.Test;
import org.operatorfoundation.shapeshifter.shadow.java.DarkStar;
import org.operatorfoundation.shapeshifter.shadow.java.ShadowConfig;
import org.operatorfoundation.shapeshifter.shadow.java.ShadowSocket;
import org.operatorfoundation.shapeshifter.shadow.java.ShadowSocketFactory;
import org.operatorfoundation.shapeshifter.shadow.java.TestServer;

import java.io.IOException;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.UUID;

/**
 * Example local unit test, which will execute on the development machine (host).
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
public class ExampleUnitTest {

    @Test
    public void serverIdentifierTest() throws UnknownHostException {
        byte[] correct = {127, 0, 0, 1, 4, (byte) 210};
        byte[] serverIdentifier = DarkStar.makeServerIdentifier("127.0.0.1", 1234);
        assertArrayEquals(correct, serverIdentifier);
        System.out.println(bytesToHex(serverIdentifier));
    }

    @Test
    public void privateKeyGenTest() {
        KeyPair clientEphemeralKey = generateECKeys();
        PrivateKey clientEphemeralPrivateKey = null;
        clientEphemeralPrivateKey = clientEphemeralKey.getPrivate();
        String format = clientEphemeralPrivateKey.getFormat();
        Log.i("DarkStar", "getFormat result: " + format);
        String encoded = DarkStar.bytesToHex(clientEphemeralPrivateKey.getEncoded(), clientEphemeralPrivateKey.getEncoded().length);
        System.out.println("private: ");
        System.out.println(encoded);
        PublicKey clientEphemeralPublicKey = clientEphemeralKey.getPublic();
        byte[] clientEphemeralKeyData = clientEphemeralPublicKey.getEncoded();
        System.out.println("public: ");
        System.out.println(DarkStar.bytesToHex(clientEphemeralKeyData, clientEphemeralKeyData.length));
        if (!(clientEphemeralPublicKey instanceof BCECPublicKey)) {
            System.out.println("could not typecast to bcec");
        }
        BCECPublicKey bcecPubKey = (BCECPublicKey) clientEphemeralPublicKey;
        byte[] encodedKey = bcecPubKey.getQ().getEncoded(true);
        System.out.println("public encoded: ");
        System.out.println(DarkStar.bytesToHex(encodedKey, encodedKey.length));
        System.out.println(encodedKey.length);
    }

    @Test
    public void shadowDarkStarClientTest() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        // TODO: Make sure the password matches the servers public key.
        ShadowConfig config = new ShadowConfig("ENTER SERVERS PUBLIC KEY", "DarkStar");
        // TODO: Use an actual server IP and port here:
        ShadowSocket shadowSocket = new ShadowSocket(config, "0.0.0.0", 1234);
        assertNotNull(shadowSocket);
        System.out.println("Initialized a shadowsocket");
        String httpRequest = "GET / HTTP/1.0\r\n\r\n";
        byte[] textBytes = httpRequest.getBytes();
        shadowSocket.getOutputStream().write(textBytes);
        System.out.println("Wrote some bytes.");
        shadowSocket.getOutputStream().flush();
        System.out.println("Flushed the output stream.");
        byte[] buffer = new byte[4];
        int bytesRead =  shadowSocket.getInputStream().read(buffer);
        System.out.print("Read some bytes: ");
        System.out.println(bytesRead);
    }

    @Test
    public void compressPublicKeyTest() throws InvalidKeySpecException, NoSuchAlgorithmException {
        String pubkeyString = "4ed5d754928698e5f73de6ff22feb516e146b7fd1a0e6ca466ccb77e2cc324bf";
        byte[] pubKeyBytes = hexToBytes(pubkeyString);
        PublicKey pubKey = bytesToPublicKey(pubKeyBytes);
        assertNotNull(pubKey);
    }

    @Test
    public void sipTest() throws IOException {
        TestServer myRunnable = new TestServer();
        Thread thread = new Thread(myRunnable);
        thread.start();
        URL url = new URL("https://raw.githubusercontent.com/OperatorFoundation/ShadowSwift/main/Tests/ShadowSwiftTests/testsip008.json");
        UUID uuid = UUID.fromString("27b8a625-4f4b-4428-9f0f-8a2317db7c79");
        ShadowSocketFactory factory = new ShadowSocketFactory(url, uuid);
        factory.createSocket();
    }
}