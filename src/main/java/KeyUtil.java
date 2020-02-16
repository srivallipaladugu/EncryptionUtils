import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class KeyUtil {
    private static final Logger LOGGER = LoggerFactory.getLogger(KeyUtil.class);

    public static void main(String[] args) {
        try {
            String encryptedString = Base64.getEncoder().encodeToString(encrypt("1q2w3e4r"));
            System.out.println(encryptedString);
            String decryptedString = KeyUtil.decrypt(encryptedString);
            System.out.println(decryptedString);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            System.out.println("Error encrypting / decrypting the text "+ e);
        }
    }

    // To generate new public and private key
    void generateNewKeyValuePair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();
            Key pub = kp.getPublic();
            Key pvt = kp.getPrivate();
            FileOutputStream out = null;
            out = new FileOutputStream("devprivate" + ".key");
            out.write(pvt.getEncoded());
            out.close();

            out = new FileOutputStream("devpublic" + ".pub");
            out.write(pub.getEncoded());
            out.close();
            System.out.println(Base64.getEncoder().encodeToString(pub.getEncoded()));
            System.out.println(Base64.getEncoder().encodeToString(pvt.getEncoded()));
            System.out.println("Private key format: " + pvt.getFormat());
            System.out.println("Public key format: " + pub.getFormat());
        } catch (Exception e) {
            System.out.println("Error generating a public and private key files {}" + e);
        }
    }

    public static PublicKey getPublicKey() {

        PublicKey publicKey = null;
        try {
            Path path = Paths.get("/apps/spectrum/MBO/mobilebackofficeconfig/devpublic.pub");
            byte[] bytes = Files.readAllBytes(path);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(bytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(keySpec);
            return publicKey;
        } catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return publicKey;
    }

    public static PrivateKey getPrivateKey() {
        PrivateKey privateKey = null;
        KeyFactory keyFactory = null;
        try {
            Path path = Paths.get("/apps/spectrum/MBO/mobilebackofficeconfig/devprivate.key");
            byte[] bytes = Files.readAllBytes(path);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
            keyFactory = KeyFactory.getInstance("RSA");
            privateKey = keyFactory.generatePrivate(keySpec);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return privateKey;
    }

    public static byte[] encrypt(String data) throws BadPaddingException, IllegalBlockSizeException,
            InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, getPublicKey());
        return cipher.doFinal(data.getBytes());
    }


    public static String decrypt(byte[] data, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(data));
    }

    public static String decrypt(String data) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        return decrypt(Base64.getDecoder().decode(data.getBytes()), getPrivateKey());
    }

}
