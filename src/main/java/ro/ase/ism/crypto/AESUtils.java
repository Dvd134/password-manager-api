package ro.ase.ism.crypto;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Objects;

import static ro.ase.ism.crypto.CryptoUtils.*;

public class AESUtils {

    public enum DataType {

        HEX,
        BASE64
    }

    private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String SECRET_KEY_ALGORITHM = "PBKDF2WithHmacSHA1";
    private static final String KEY_ALGORITHM = "AES";

    private final int BATCH_SIZE = 1024;
    private final int IV_SIZE = 128;
    private int iterationCount = 1989;
    private int keySize = 256;
    private int saltLength;

    private DataType dataType;
    private Cipher cipher;

    public AESUtils() {

        dataType = DataType.BASE64;
        try {

            cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            saltLength = this.keySize / 4;
        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {

            e.printStackTrace();
        }
    }

    public AESUtils(int keySize, int iterationCount) {

        dataType = DataType.BASE64;
        this.keySize = keySize;
        this.iterationCount = iterationCount;
        try {

            cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            saltLength = this.keySize / 4;
        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {

            e.printStackTrace();
        }
    }

    public String encrypt(String salt, String iv, String passPhrase, String plainText) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {

        SecretKey secretKey = generateKey(salt, passPhrase);
        byte[] encrypted = doFinal(Cipher.ENCRYPT_MODE, secretKey, iv, plainText.getBytes(StandardCharsets.UTF_8));
        String cipherText = dataType.equals(DataType.HEX) ? byteToHex(encrypted) : byteToBase64(encrypted);

        return cipherText;
    }

    public String encrypt(String passPhrase, String plainText) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, IllegalBlockSizeException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {

        String salt = byteToHex(getRandomBytes(keySize / 8, null));
        String iv = byteToHex(getRandomBytes(IV_SIZE / 8, null));
        String cipherText = encrypt(salt, iv, passPhrase, plainText);
        return salt + iv + cipherText;
    }

    public String encryptFileContent(String passPhrase, String plainText) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, IllegalBlockSizeException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {

        String salt = byteToHex(getRandomBytes(keySize / 8, null));
        String iv = byteToHex(getRandomBytes(IV_SIZE / 8, null));
        StringBuilder cipherText = new StringBuilder();
        dataType = DataType.HEX;

        for(int i = 0 ; i < plainText.length() ; i += BATCH_SIZE) {

            int endIndex = Math.min(i + BATCH_SIZE, plainText.length());
            String batch = plainText.substring(i, endIndex);
            cipherText.append(encrypt(salt, iv, passPhrase, batch));
        }

        dataType = DataType.BASE64;
        return salt + iv + cipherText;
    }

    public String decryptFileContent(String passPhrase, String cipherText) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, IllegalBlockSizeException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {

        String salt = cipherText.substring(0, saltLength);
        int ivLength = IV_SIZE / 4;
        String iv = cipherText.substring(saltLength, saltLength + ivLength);
        String ct = cipherText.substring(saltLength + ivLength);
        StringBuilder plainText = new StringBuilder();
        dataType = DataType.HEX;

        for(int i = 0 ; i < ct.length() ; i += BATCH_SIZE) {

            int endIndex = Math.min(i + BATCH_SIZE, ct.length());
            String batch = ct.substring(i, endIndex);
            plainText.append(decrypt(salt, iv, passPhrase, batch));
        }

        dataType = DataType.BASE64;
        return plainText.toString();
    }

    public String decrypt(String salt, String iv, String passPhrase, String cipherText) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {

        SecretKey key = generateKey(salt, passPhrase);
        byte[] encrypted = dataType.equals(DataType.HEX) ? hexToByte(cipherText) : base64ToByte(cipherText);
        byte[] decrypted = doFinal(Cipher.DECRYPT_MODE, key, iv, encrypted);
        return new String(Objects.requireNonNull(decrypted), StandardCharsets.UTF_8);
    }

    public String decrypt(String passPhrase, String cipherText) throws InvalidAlgorithmParameterException, IllegalBlockSizeException, InvalidKeySpecException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {

        String salt = cipherText.substring(0, saltLength);
        int ivLength = IV_SIZE / 4;
        String iv = cipherText.substring(saltLength, saltLength + ivLength);
        String ct = cipherText.substring(saltLength + ivLength);
        return decrypt(salt, iv, passPhrase, ct);
    }

    private SecretKey generateKey(String salt, String passPhrase) throws InvalidKeySpecException, NoSuchAlgorithmException {

        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(SECRET_KEY_ALGORITHM);
        KeySpec keySpec = new PBEKeySpec(passPhrase.toCharArray(), hexToByte(salt), iterationCount, keySize);
        return new SecretKeySpec(secretKeyFactory.generateSecret(keySpec).getEncoded(), KEY_ALGORITHM);
    }

    private byte[] doFinal(int mode, SecretKey secretKey, String iv, byte[] bytes) throws InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        cipher.init(mode, secretKey, new IvParameterSpec(hexToByte(iv)));
        return cipher.doFinal(bytes);
    }

}

