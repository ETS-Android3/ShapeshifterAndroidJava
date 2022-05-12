package org.operatorfoundation.shapeshifter.shadow.java;

import android.util.Log;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


public class DarkStar
{
    public SecretKey sharedKeyClientToServer;
    public SecretKey sharedKeyServerToClient;
    KeyPair clientEphemeralKeyPair;
    PublicKey serverPersistentPublicKey;

    static byte[] darkStarBytes = "DarkStar".getBytes();
    static byte[] clientStringBytes = "client".getBytes();
    static byte[] serverStringBytes = "server".getBytes();

    ShadowConfig shadowConfig;
    String host;
    int port;

    public DarkStar(ShadowConfig config, String host, int port) {
        this.shadowConfig = config;
        this.host = host;
        this.port = port;
    }

    public byte[] createHandshake() throws NoSuchAlgorithmException, InvalidKeySpecException, UnknownHostException
    {
        // take ServerPersistentPublicKey out of password string
        byte[] serverPersistentPublicKeyData = hexToBytes(shadowConfig.password);
        this.serverPersistentPublicKey = bytesToPublicKey(serverPersistentPublicKeyData);

        // generate an ephemeral keypair
        this.clientEphemeralKeyPair = generateECKeys();

        // get the client ephemeral private and public keys from the key pair
        PrivateKey clientEphemeralPrivateKey = null;
        PublicKey clientEphemeralPublicKey = null;

        if (this.clientEphemeralKeyPair != null)
        {
            clientEphemeralPrivateKey = this.clientEphemeralKeyPair.getPrivate();
            clientEphemeralPublicKey = this.clientEphemeralKeyPair.getPublic();
        }

        // convert the ephemeral public key into data and save it to the handshakeData array.
        byte[] handshakeData = publicKeyToBytes(clientEphemeralPublicKey);

        // Generate client confirmation code
        byte[] clientConfirmationCode = generateClientConfirmationCode(host, port, serverPersistentPublicKey, clientEphemeralPublicKey, clientEphemeralPrivateKey);

        // add the clientConfirmationCode to the handshake array.
        // handshakeData is clientEphemeralPublicKey data plus the clientConfirmationCode.
        handshakeData = Utility.plusEqualsByteArray(handshakeData, clientConfirmationCode);

        return handshakeData;
    }

    public void splitHandshake(byte[] handshakeData, byte[] ephemeralPublicKeyBuf, byte[] confirmationCodeBuf)
    {
        if (handshakeData.length != 64)
        {
            Log.e("DarkStar", "incorrect handshake size")            ;
        }

        System.arraycopy(handshakeData, 0, ephemeralPublicKeyBuf, 0, 32);
        System.arraycopy(handshakeData, 32, confirmationCodeBuf, 0, 32);
    }

    public ShadowCipher makeCipher(boolean isClientToServer, byte[] handshakeBytes) throws InvalidKeySpecException, NoSuchAlgorithmException, UnknownHostException, InvalidKeyException
    {
        byte[] serverEphemeralPublicKeyData = new byte[32];
        byte[] serverConfirmationCode = new byte[32];
        splitHandshake(handshakeBytes, serverEphemeralPublicKeyData, serverConfirmationCode);

        // turn the server's public key data back to a public key type
        PublicKey serverEphemeralPublicKey = bytesToPublicKey(serverEphemeralPublicKeyData);

        // derive shared keys
        SecretKey sharedKey = generateSharedKey(
                isClientToServer,
                host,
                port,
                clientEphemeralKeyPair,
                serverEphemeralPublicKey,
                serverPersistentPublicKey);

        if (isClientToServer)
        {
            sharedKeyClientToServer = sharedKey;
        }
        else
        {
            sharedKeyServerToClient = sharedKey;
        }

        // check confirmationCode
        byte[] clientCopyServerConfirmationCode = generateServerConfirmationCode(
                host,
                port,
                clientEphemeralKeyPair.getPublic(),
                clientEphemeralKeyPair.getPrivate(),
                serverPersistentPublicKey);
        if (!Arrays.equals(clientCopyServerConfirmationCode, serverConfirmationCode))
        {
            throw new InvalidKeyException();
        }

        if (isClientToServer)
        {
            return new ShadowDarkStarCipher(sharedKeyClientToServer);
        }
        else
        {
            return new ShadowDarkStarCipher(sharedKeyServerToClient);
        }
    }

    public static KeyPair generateECKeys()
    {
        try
        {
            ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
            keyPairGenerator.initialize(parameterSpec);
            return keyPairGenerator.generateKeyPair();
        }
        catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e)
        {
            e.printStackTrace();
            return null;
        }
    }

    public static KeyPair loadECKeys(String privateKeyString, String publicKeyString) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());

            byte[] privateKeyBytes = hexToBytes(privateKeyString);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKeyBytes);
            PrivateKey privateKey = keyFactory.generatePrivate(spec);

            byte[] publicKeyBytes = hexToBytes(publicKeyString);
            PublicKey publicKey = bytesToPublicKey(publicKeyBytes);

            return new KeyPair(publicKey, privateKey);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static SecretKey generateSharedSecret(PrivateKey privateKey, PublicKey publicKey)
    {
        try
        {
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", new BouncyCastleProvider());
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(publicKey, true);
            return keyAgreement.generateSecret("secp256r1");
        }
        catch (InvalidKeyException | NoSuchAlgorithmException e)
        {
            e.printStackTrace();
            return null;
        }
    }

    public static SecretKey generateSharedKey(boolean isClientToServer, String host, int port, KeyPair clientEphemeral, PublicKey serverEphemeralPublicKey, PublicKey serverPersistentPublicKey) throws UnknownHostException, NoSuchAlgorithmException
    {
        SecretKey ecdh1 = DarkStar.generateSharedSecret(clientEphemeral.getPrivate(), serverEphemeralPublicKey);
        SecretKey ecdh2 = DarkStar.generateSharedSecret(clientEphemeral.getPrivate(), serverPersistentPublicKey);
        byte[] serverIdentifier = DarkStar.makeServerIdentifier(host, port);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        if (ecdh1 != null)
        {
            digest.update(ecdh1.getEncoded());
        }

        if (ecdh2 != null)
        {
            digest.update(ecdh2.getEncoded());
        }

        digest.update(serverIdentifier);
        digest.update(publicKeyToBytes(clientEphemeral.getPublic()));
        digest.update(publicKeyToBytes(serverEphemeralPublicKey));
        digest.update(darkStarBytes);

        if (isClientToServer)
        {
            digest.update(serverStringBytes);
        }
        else
        {
            digest.update(clientStringBytes);
        }
        byte[] result = digest.digest();

        return new SecretKeySpec(result, 0, result.length, "AES");
    }

    public static byte[] makeServerIdentifier(String host, int port) throws UnknownHostException
    {
        InetAddress ip = InetAddress.getByName(host);
        byte[] address = ip.getAddress();
        ByteBuffer buf = ByteBuffer.allocate(2);
        buf.putShort((short) port);
        byte[] portBytes = buf.array();

        return Utility.plusEqualsByteArray(address, portBytes);
    }

    public static byte[] generateServerConfirmationCode(String host, int port, PublicKey clientEphemeralPublicKey, PrivateKey clientEphemeralPrivateKey, PublicKey serverPersistentPublicKey) throws NoSuchAlgorithmException, UnknownHostException, InvalidKeyException
    {
        byte[] serverIdentifier = makeServerIdentifier(host, port);
        byte[] serverPersistentPublicKeyData = publicKeyToBytes(serverPersistentPublicKey);
        byte[] clientEphemeralPublicKeyData = publicKeyToBytes(clientEphemeralPublicKey);
        SecretKey sharedSecret = generateSharedSecret(clientEphemeralPrivateKey, serverPersistentPublicKey);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        if (sharedSecret != null)
        {
            digest.update(sharedSecret.getEncoded());
        }

        digest.update(serverIdentifier);
        digest.update(serverPersistentPublicKeyData);
        digest.update(clientEphemeralPublicKeyData);
        digest.update(darkStarBytes);
        digest.update(serverStringBytes);

        return digest.digest();
    }

    public static byte[] generateClientConfirmationCode(String host, int port, PublicKey serverPersistentPublicKey, PublicKey clientEphemeralPublicKey, PrivateKey clientEphemeralPrivateKey) throws NoSuchAlgorithmException, UnknownHostException
    {
        SecretKey sharedSecret = DarkStar.generateSharedSecret(clientEphemeralPrivateKey, serverPersistentPublicKey);
        byte[] serverIdentifier = makeServerIdentifier(host, port);
        byte[] serverPersistentPublicKeyData = publicKeyToBytes(serverPersistentPublicKey);
        byte[] clientEphemeralPublicKeyData = publicKeyToBytes(clientEphemeralPublicKey);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        if (sharedSecret != null)
        {
            digest.update(sharedSecret.getEncoded());
        }

        digest.update(serverIdentifier);
        digest.update(serverPersistentPublicKeyData);
        digest.update(clientEphemeralPublicKeyData);
        digest.update(darkStarBytes);
        digest.update(clientStringBytes);

        return digest.digest();
    }

    public static byte[] publicKeyToBytes(PublicKey pubKey) {
        BCECPublicKey bcecPublicKey = (BCECPublicKey) pubKey;
        ECPoint point = bcecPublicKey.getQ();
        byte[] encodedPoint = point.getEncoded(true);
        byte[] result = new byte[32];
        System.arraycopy(encodedPoint, 1, result, 0, 32);
        return result;
    }

    public static PublicKey bytesToPublicKey(byte[] bytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
        byte[] encodedPoint = new byte[33];
        System.arraycopy(bytes, 0, encodedPoint, 1, 32);
        encodedPoint[0] = 3;
        ECPoint point = ecSpec.getCurve().decodePoint(encodedPoint);
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, ecSpec);
        return keyFactory.generatePublic(pubSpec);
    }

    public static String bytesToHex(byte[] data, int length) {
        String digits = "0123456789ABCDEF";
        StringBuilder buffer = new StringBuilder();

        for (int i = 0; i != length; i++) {
            int v = data[i] & 0xff;

            buffer.append(digits.charAt(v >> 4));
            buffer.append(digits.charAt(v & 0xf));
        }

        return buffer.toString();
    }

    public static String bytesToHex(byte[] data) {
        return bytesToHex(data, data.length);
    }

    public static byte[] hexToBytes(String string) {
        int length = string.length();
        byte[] data = new byte[length / 2];
        for (int i = 0; i < length; i += 2) {
            data[i / 2] = (byte) ((Character.digit(string.charAt(i), 16) << 4) + Character
                    .digit(string.charAt(i + 1), 16));
        }
        return data;
    }
}