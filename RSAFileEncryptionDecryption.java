

import java.io.*;
import java.nio.file.*;
import java.security.*;
import javax.crypto.*;

public class RSAFileEncryption {


    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        return keyPairGen.generateKeyPair();
    }

    public static byte[] encryptData(byte[] data, PublicKey publicKey) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    public static byte[] decryptData(byte[] encryptedData, PrivateKey privateKey) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedData);
    }

    public static void writeToFile(byte[] data, Path path) throws IOException {
        Files.write(path, data);
    }

    public static byte[] readFromFile(Path path) throws IOException {
        return Files.readAllBytes(path);
    }

    public static void main(String[] args) {
        try {
            // Generate RSA Key Pair
            KeyPair keyPair = generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            Path inputFile = Paths.get("<FILE_NAME/PATH>");
            Path encryptedFile = Paths.get("<FILE_NAME/PATH>");
            Path decryptedFile = Paths.get("<FILE_NAME/PATH>");

            if (!Files.exists(inputFile)) {
                System.err.println("Input file not found: " + inputFile.toAbsolutePath());
                return;
            }

            byte[] fileData = readFromFile(inputFile);

            byte[] encryptedData = encryptData(fileData, publicKey);
            writeToFile(encryptedData, encryptedFile);

            byte[] decryptedData = decryptData(encryptedData, privateKey);
            writeToFile(decryptedData, decryptedFile);

            System.out.println("Encryption and decryption complete.");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

