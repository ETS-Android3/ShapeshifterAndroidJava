package org.operatorfoundation.shadow;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Test;
import org.operatorfoundation.shapeshifter.shadow.java.DarkStar;
import org.operatorfoundation.shapeshifter.shadow.java.ShadowConfig;
import org.operatorfoundation.shapeshifter.shadow.java.ShadowDarkStarCipher;
import org.operatorfoundation.shapeshifter.shadow.java.ShadowSocket;
import org.operatorfoundation.shapeshifter.shadow.java.ShadowSocketFactory;
import org.operatorfoundation.shapeshifter.shadow.java.TestServer;

import java.io.IOException;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.UUID;

import javax.crypto.SecretKey;
import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.operatorfoundation.shapeshifter.shadow.java.DarkStar.bytesToHex;
import static org.operatorfoundation.shapeshifter.shadow.java.DarkStar.bytesToPublicKey;
import static org.operatorfoundation.shapeshifter.shadow.java.DarkStar.generateECKeys;
import static org.operatorfoundation.shapeshifter.shadow.java.DarkStar.generateSharedKey;
import static org.operatorfoundation.shapeshifter.shadow.java.DarkStar.hexToBytes;

import android.util.Log;

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
        // generate public key on swift for SPPK
        // pass 1: recent: 03d089c225ef8cda8d477a586f062b31a756270124d94944e458edf1a9e1e41ed6
        // old pass: 3059301306072a8648ce3d020106082a8648ce3d030107034200044ed5d754928698e5f73de6ff22feb516e146b7fd1a0e6ca466ccb77e2cc324bf3deb2b4df4d7583b521ecd466f37e84b8f7930482ca2a0d18baffd353fb207fd
        ShadowConfig config = new ShadowConfig("d089c225ef8cda8d477a586f062b31a756270124d94944e458edf1a9e1e41ed6", "DarkStar");
        ShadowSocket shadowSocket = new ShadowSocket(config, "127.0.0.1", 1234);
        assertNotNull(shadowSocket);
        String httpRequest = "GET / HTTP/1.0\r\n\r\n";
        byte[] textBytes = httpRequest.getBytes();
        shadowSocket.getOutputStream().write(textBytes);
        shadowSocket.getOutputStream().flush();
        byte[] buffer = new byte[4];
        shadowSocket.getInputStream().read(buffer);
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