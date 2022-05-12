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
import org.operatorfoundation.shapeshifter.shadow.java.ShadowSocketFactory;

import java.io.IOException;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.UUID;

/**
 * Example local unit test, which will execute on the development machine (host).
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
public class ExampleUnitTest
{
    @Test
    public void serverIdentifierTest() throws UnknownHostException
    {
        byte[] correct = {127, 0, 0, 1, 4, (byte) 210};
        byte[] serverIdentifier = DarkStar.makeServerIdentifier("127.0.0.1", 1234);
        assertArrayEquals(correct, serverIdentifier);
        System.out.println(bytesToHex(serverIdentifier));
    }

    @Test
    public void privateKeyGenTest()
    {
        // Get key pair
        KeyPair clientEphemeralKey = generateECKeys();
        assert clientEphemeralKey != null;

        // Private key
        PrivateKey clientEphemeralPrivateKey = clientEphemeralKey.getPrivate();
        String format = clientEphemeralPrivateKey.getFormat();
        Log.i("DarkStar", "getFormat result: " + format);
        String encoded = DarkStar.bytesToHex(clientEphemeralPrivateKey.getEncoded(), clientEphemeralPrivateKey.getEncoded().length);
        System.out.println("private: ");
        System.out.println(encoded);

        // Public Key
        PublicKey clientEphemeralPublicKey = clientEphemeralKey.getPublic();
        byte[] clientEphemeralKeyData = clientEphemeralPublicKey.getEncoded();
        System.out.println("public: ");
        System.out.println(DarkStar.bytesToHex(clientEphemeralKeyData, clientEphemeralKeyData.length));

        // Encoded Public Key
        assert clientEphemeralPublicKey instanceof BCECPublicKey;
        BCECPublicKey bcecPubKey = (BCECPublicKey) clientEphemeralPublicKey;
        byte[] encodedKey = bcecPubKey.getQ().getEncoded(true);
        System.out.println("public encoded: ");
        System.out.println(DarkStar.bytesToHex(encodedKey, encodedKey.length));
        System.out.println(encodedKey.length);
    }

    @Test
    public void compressPublicKeyTest() throws InvalidKeySpecException, NoSuchAlgorithmException
    {
        String pubkeyString = "4ed5d754928698e5f73de6ff22feb516e146b7fd1a0e6ca466ccb77e2cc324bf";
        byte[] pubKeyBytes = hexToBytes(pubkeyString);
        PublicKey pubKey = bytesToPublicKey(pubKeyBytes);
        assertNotNull(pubKey);
    }

    @Test
    public void createFactoryTest() throws IOException
    {
        URL url = new URL("https://raw.githubusercontent.com/OperatorFoundation/ShadowSwift/main/Tests/ShadowSwiftTests/testsip008.json");
        UUID uuid = UUID.fromString("27b8a625-4f4b-4428-9f0f-8a2317db7c79");
        ShadowSocketFactory factory = new ShadowSocketFactory(url, uuid);
        assertNotNull(factory);
    }
}