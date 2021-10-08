package org.operatorfoundation.shapeshifter.shadow.java;

import android.util.Log;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.*;


public class DarkStar {
    public static byte[] iv = new SecureRandom().generateSeed(16);
    public static int P256KeySize = 32;
    public static int ConfirmationSize = 32;
    public SecretKey sharedKeyClient;
    public SecretKey decryptKey;
    static byte[] darkStarBytes = "DarkStar".getBytes();
    static byte[] clientStringBytes = "client".getBytes();
    static byte[] serverStringBytes = "server".getBytes();

    public DarkStar(InputStream inputStream, OutputStream outputStream, String host, int port, KeyPair serverPersistentKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        // generate an ephemeral keypair
        KeyPair clientEphemeralKey = generateECKeys();

        // get the client private and public key
        PrivateKey clientEphemeralPrivateKey = null;
        PublicKey clientEphemeralPublicKey = null;
        if (clientEphemeralKey != null) {
            clientEphemeralPrivateKey = clientEphemeralKey.getPrivate();
            clientEphemeralPublicKey = clientEphemeralKey.getPublic();
        }
        if (!(clientEphemeralPublicKey instanceof BCECPublicKey)) {
            System.out.println("could not typecast to bcec");
        }

        // convert the public key into data to be sent to the server
        byte[] clientEphemeralPublicKeyData = publicKeyToBytes(clientEphemeralPublicKey);

        // send the public key to the server
        outputStream.write(clientEphemeralPublicKeyData);
        
        // receive the ephemeral public key from the server
        byte[] serverEphemeralPublicKeyData = new byte[P256KeySize];
        int serverBytesRead = inputStream.read(serverEphemeralPublicKeyData);
        if (serverBytesRead != P256KeySize) {
            Log.e("DarkStar", "Failed to read the server's ephemeral public key data");
        }

        // turn the server's public key data back to a public key type
        PublicKey serverEphemeralPublicKey = bytesToPublicKey(serverEphemeralPublicKeyData);

        // derive shared keys
        // FIXME: make separate function for encrypt and decrypt key
        sharedKeyClient = generateSharedKeyClient(host, port, clientEphemeralKey, serverEphemeralPublicKey, serverPersistentKey.getPublic());

        // Generate client confirmation code
         byte[] clientConfirmationCode = generateClientConfirmationCode(host, port, serverEphemeralPublicKey, clientEphemeralPublicKey, clientEphemeralPrivateKey);

        // Receive server confirmation code
        byte[] serverConfirmationCode = new byte[ConfirmationSize];
        int serverConfirmationBytesRead = inputStream.read(serverConfirmationCode);
        if (serverConfirmationBytesRead != ConfirmationSize) {
            Log.e("DarkStar", "Failed to read the server's confirmation code");
        }

        if (serverConfirmationCode != clientConfirmationCode) {
            Log.e("DarkStar", "client and server confirmation code do not match");
        }
    }

    public static KeyPair generateECKeys() {
        try {
            ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                    "EC", new BouncyCastleProvider());

            keyPairGenerator.initialize(parameterSpec);

            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
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
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            return new KeyPair(publicKey, privateKey);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static SecretKey generateSharedSecret(PrivateKey privateKey, PublicKey publicKey) {
        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", new BouncyCastleProvider());
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(publicKey, true);

            SecretKey key = keyAgreement.generateSecret("secp256r1");
            return key;
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }
    }

//    public static SecretKey generateSharedKeyServer(String host, int port, KeyPair serverEphemeral, KeyPair serverPersistent, PublicKey clientEphemeralPublicKey) throws UnknownHostException, NoSuchAlgorithmException {
//        SecretKey ecdh1 = DarkStar.generateSharedSecret(serverEphemeral.getPrivate(), clientEphemeralPublicKey);
//        SecretKey ecdh2 = DarkStar.generateSharedSecret(serverPersistent.getPrivate(), clientEphemeralPublicKey);
//        byte[] serverIdentifier = DarkStar.makeServerIdentifier(host, port);
//        MessageDigest digest = MessageDigest.getInstance("SHA-256");
//        digest.update(ecdh1.getEncoded());
//        digest.update(ecdh2.getEncoded());
//        digest.update(serverIdentifier);
//        digest.update(publicKeyToBytes(clientEphemeralPublicKey));
//        digest.update(publicKeyToBytes(serverEphemeral.getPublic()));
//        digest.update(darkStarBytes);
//        byte[] result = digest.digest();
//
//        return new SecretKeySpec(result, 0, result.length, "AES");
//    }

    public static SecretKey generateSharedKeyClient(String host, int port, KeyPair clientEphemeral, PublicKey serverEphemeralPublicKey, PublicKey serverPersistentPublicKey) throws UnknownHostException, NoSuchAlgorithmException {
        SecretKey ecdh1 = DarkStar.generateSharedSecret(clientEphemeral.getPrivate(), serverEphemeralPublicKey);
        SecretKey ecdh2 = DarkStar.generateSharedSecret(clientEphemeral.getPrivate(), serverPersistentPublicKey);
        byte[] serverIdentifier = DarkStar.makeServerIdentifier(host, port);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(ecdh1.getEncoded());
        digest.update(ecdh2.getEncoded());
        digest.update(serverIdentifier);
        digest.update(publicKeyToBytes(clientEphemeral.getPublic()));
        digest.update(publicKeyToBytes(serverEphemeralPublicKey));
        digest.update(darkStarBytes);
        byte[] result = digest.digest();

        return new SecretKeySpec(result, 0, result.length, "AES");
    }

    public static byte[] makeServerIdentifier(String host, int port) throws UnknownHostException {
        InetAddress ip = InetAddress.getByName(host);
        byte[] address = ip.getAddress();
        ByteBuffer buf = ByteBuffer.allocate(2);
        buf.putShort((short) port);
        byte[] portBytes = buf.array();

        return Utility.plusEqualsByteArray(address, portBytes);
    }

    public static byte[] generateServerConfirmationCode(String host, int port, PublicKey serverEphemeralPublicKey, PublicKey clientEphemeralPublicKey, SecretKey sharedKey) throws NoSuchAlgorithmException, UnknownHostException, InvalidKeyException {
        byte[] serverIdentifier = makeServerIdentifier(host, port);
        byte[] serverEphemeralPublicKeyData = serverEphemeralPublicKey.getEncoded();
        byte[] clientEphemeralPublicKeyData = clientEphemeralPublicKey.getEncoded();

        SecretKeySpec secretKeySpec = new SecretKeySpec(sharedKey.getEncoded(), "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secretKeySpec);
        mac.update(serverIdentifier);
        mac.update(serverEphemeralPublicKeyData);
        mac.update(clientEphemeralPublicKeyData);
        mac.update(darkStarBytes);
        mac.update(clientStringBytes);

        return mac.doFinal();
    }

    public static byte[] generateClientConfirmationCode(String host, int port, PublicKey serverPersistentPublicKey, PublicKey clientEphemeralPublicKey, PrivateKey clientEphemeralPrivateKey) throws NoSuchAlgorithmException, UnknownHostException {
        SecretKey sharedSecret = DarkStar.generateSharedSecret(clientEphemeralPrivateKey, serverPersistentPublicKey);
        byte[] serverIdentifier = makeServerIdentifier(host, port);
        byte[] serverPersistentPublicKeyData = serverPersistentPublicKey.getEncoded();
        byte[] clientEphemeralPublicKeyData = clientEphemeralPublicKey.getEncoded();

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(sharedSecret.getEncoded());
        digest.update(serverIdentifier);
        digest.update(serverPersistentPublicKeyData);
        digest.update(clientEphemeralPublicKeyData);
        digest.update(darkStarBytes);
        digest.update(serverStringBytes);

        return digest.digest();
    }

    public static byte[] publicKeyToBytes(PublicKey pubKey) {
        if (!(pubKey instanceof BCECPublicKey)) {
            System.out.println("could not typecast to bcec");
        }
        BCECPublicKey bcecPubKey = (BCECPublicKey) pubKey;
        return bcecPubKey.getQ().getEncoded(true);
    }

    public static PublicKey bytesToPublicKey(byte[] bytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
        ECPoint point = ecSpec.getCurve().decodePoint(bytes);
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, ecSpec);
        KeyFactory kf = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        return kf.generatePublic(pubSpec);
    }

    public static String bytesToHex(byte[] data, int length) {
        String digits = "0123456789ABCDEF";
        StringBuffer buffer = new StringBuffer();

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