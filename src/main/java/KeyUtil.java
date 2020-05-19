import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import org.bouncycastle.jcajce.provider.symmetric.AES;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class KeyUtil {
    private static final Logger LOGGER = LoggerFactory.getLogger(KeyUtil.class);

    public static void main(String[] args) {
        // To encrypt/decrypt using RSA/Asymmetric encryption
        try {
            RSAEncryptionUtil.generateNewKeyValuePair();
            String encryptedString = Base64.getEncoder().encodeToString(RSAEncryptionUtil.encrypt("1q2w3e4r"));
            System.out.println(encryptedString);
            String decryptedString = RSAEncryptionUtil.decrypt(encryptedString);
            System.out.println(decryptedString);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            System.out.println("Error encrypting / decrypting the text "+ e);
        }

        AESEncryptionUtil.generateAESKey();
        String originalString = "password";
        System.out.println("Original String to encrypt - " + originalString);
        String encryptedString = AESEncryptionUtil.encrypt(originalString);
        System.out.println("Encrypted String - " + encryptedString);
        String decryptedString = AESEncryptionUtil.decrypt(encryptedString);
        System.out.println("After decryption - " + decryptedString);

    }
}
