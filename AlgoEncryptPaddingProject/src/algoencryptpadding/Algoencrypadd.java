package algoencryptpadding;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

//import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;


public class Algoencrypadd {

	
	
	    private static final String AES_ALGORITHM = "AES";
	    private static final String RSA_ALGORITHM = "RSA";
	    private static final int GCM_IV_LENGTH = 12; // 96 bits
	    private static final int GCM_TAG_LENGTH = 128; // 128 bits
	    private static String TRANSFORMATION = "";

	    public static void main(String[] args) {
	        Scanner sc = new Scanner(System.in);

	        System.out.println("Enter the input text:");
	        String input = sc.nextLine();

	        System.out.println("Enter the algorithm (AES/RSA):");
	        String algorithm = sc.nextLine();

	        System.out.println("Enter the encryption mode (ECB/CBC/GCM):");
	        String encryptionMode = sc.nextLine();

	        System.out.println("Enter the padding mode (PKCS5/NoPadding):");
	        String padding = sc.nextLine();

	        String result = EncryptionDecryption(input, algorithm, encryptionMode, padding);
	        System.out.println("Decrypted Result: " + result);
	    }

	    public static String EncryptionDecryption(String input, String algorithm, String encryptionMode, String padding) {
	        try {
	            TRANSFORMATION = algorithm + "/" + encryptionMode + "/" + (padding.equalsIgnoreCase("NoPadding") ? "NoPadding" : "PKCS5Padding");

	            if (algorithm.equalsIgnoreCase(AES_ALGORITHM) && encryptionMode.equalsIgnoreCase("GCM")) {
	                SecretKey secretKey = generateAESKey();
	                byte[] iv = new byte[GCM_IV_LENGTH];
	                SecureRandom.getInstanceStrong().nextBytes(iv);
	                String encryptedText = encrypt(input, secretKey, iv);
	                return encryptedText + ";" + decrypt(encryptedText, secretKey, iv);
	            } else if (algorithm.equalsIgnoreCase(RSA_ALGORITHM)) {
	                KeyPair keyPair = generateRSAKeyPair();
	                String encryptedText = encrypt(input, keyPair.getPublic());
	                return encryptedText + ";" + decrypt(encryptedText, keyPair.getPrivate());
	            } else {
	                System.out.println("Invalid algorithm or encryption mode. Please enter 'AES/GCM' or 'RSA'.");
	                return "";
	            }
	        } catch (Exception e) {
	            e.printStackTrace();
	            return "";
	        }
	    }

	    private static SecretKey generateAESKey() throws Exception {
	        KeyGenerator keyGen = KeyGenerator.getInstance(AES_ALGORITHM);
	        keyGen.init(256);
	        return keyGen.generateKey();
	    }

	    private static KeyPair generateRSAKeyPair() throws Exception {
	        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA_ALGORITHM);
	        keyGen.initialize(2048);
	        return keyGen.generateKeyPair();
	    }

	    private static String encrypt(String input, SecretKey key, byte[] iv) throws Exception {
	        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
	        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
	        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
	        byte[] encryptedBytes = cipher.doFinal(input.getBytes());
	        
	        byte[] encryptedTextWithIv = new byte[GCM_IV_LENGTH + encryptedBytes.length];
	        System.arraycopy(iv, 0, encryptedTextWithIv, 0, GCM_IV_LENGTH);
	        System.arraycopy(encryptedBytes, 0, encryptedTextWithIv, GCM_IV_LENGTH, encryptedBytes.length);
	        
	        return Base64.getEncoder().encodeToString(encryptedTextWithIv);
	    }

	    private static String encrypt(String input, PublicKey key) throws Exception {
	        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
	        cipher.init(Cipher.ENCRYPT_MODE, key);
	        byte[] encryptedBytes = cipher.doFinal(input.getBytes());
	        return Base64.getEncoder().encodeToString(encryptedBytes);
	    }

	    private static String decrypt(String input, SecretKey key, byte[] iv) throws Exception {
	        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
	        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
	        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
	        byte[] decodedBytes = Base64.getDecoder().decode(input);
	        byte[] decryptedBytes = cipher.doFinal(decodedBytes, GCM_IV_LENGTH, decodedBytes.length - GCM_IV_LENGTH);
	        return new String(decryptedBytes).trim();
	    }

	    private static String decrypt(String input, PrivateKey key) throws Exception {
	        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
	        cipher.init(Cipher.DECRYPT_MODE, key);
	        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(input));
	        return new String(decryptedBytes).trim();
	    }
	}

	
	
	
	/*
	    private static final String AES_ALGORITHM = "AES";
	    private static final String RSA_ALGORITHM = "RSA";
	    private static String TRANSFORMATION = "";

	    public static void main(String[] args) {
	        Scanner sc = new Scanner(System.in);
	        
	        System.out.println("Enter the input text:");
	        String input = sc.nextLine();
	        
	        System.out.println("Enter the algorithm (AES/RSA):");
	        String algorithm = sc.nextLine();
	        
	        System.out.println("Enter the encryption mode (ECB/CBC):");
	        String encryptionMode = sc.nextLine();
	        
	        System.out.println("Enter the padding mode (PKCS5/NoPadding):");
	        String padding = sc.nextLine();
	        
	        String result = EncryptionDecryption(input, algorithm, encryptionMode, padding);
	        System.out.println("Decrypted Result: " + result);
	    }

	    public static String EncryptionDecryption(String input, String algorithm, String encryptionMode, String padding) {
	        try {
	            TRANSFORMATION = algorithm + "/" + encryptionMode + "/" + (padding.equalsIgnoreCase("NoPadding") ? "NoPadding" : "PKCS5Padding");

	            if (algorithm.equalsIgnoreCase(AES_ALGORITHM)) {
	                SecretKey secretKey = generateAESKey();
	                String encryptedText = encrypt(input, secretKey);
	                //System.out.println("Encrypted Text (AES): " + encryptedText);
	                //return decrypt(encryptedText, secretKey);
	                return encryptedText+";"+decrypt(encryptedText, secretKey);
	            } 
	            else if (algorithm.equalsIgnoreCase(RSA_ALGORITHM)) {
	                KeyPair keyPair = generateRSAKeyPair();
	                String encryptedText = encrypt(input, keyPair.getPublic());
	                //System.out.println("Encrypted Text (RSA): " + encryptedText);
	                return encryptedText+";"+ decrypt(encryptedText, keyPair.getPrivate());
	            } 
	            else {
	                System.out.println("Invalid algorithm. Please enter 'AES' or 'RSA'.");
	                return "";
	            }
	        } catch (Exception e) {
	            e.printStackTrace();
	            return "";
	        }
	    }

	    private static SecretKey generateAESKey() throws Exception {
	        KeyGenerator keyGen = KeyGenerator.getInstance(AES_ALGORITHM);
	        keyGen.init(256);
	        return keyGen.generateKey();
	    }

	    private static KeyPair generateRSAKeyPair() throws Exception {
	        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA_ALGORITHM);
	        keyGen.initialize(2048);
	        return keyGen.generateKeyPair();
	    }

	    private static String encrypt(String input, SecretKey key) throws Exception {
	        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
	        cipher.init(Cipher.ENCRYPT_MODE, key);
	        byte[] encryptedBytes = cipher.doFinal(input.getBytes());
	        return Base64.getEncoder().encodeToString(encryptedBytes);
	    }

	    private static String encrypt(String input, PublicKey key) throws Exception {
	        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
	        cipher.init(Cipher.ENCRYPT_MODE, key);
	        byte[] encryptedBytes = cipher.doFinal(input.getBytes());
	        return Base64.getEncoder().encodeToString(encryptedBytes);
	    }

	    private static String decrypt(String input, SecretKey key) throws Exception {
	        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
	        cipher.init(Cipher.DECRYPT_MODE, key);
	        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(input));
	        return new String(decryptedBytes).trim();
	    }

	    private static String decrypt(String input, PrivateKey key) throws Exception {
	        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
	        cipher.init(Cipher.DECRYPT_MODE, key);
	        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(input));
	        return new String(decryptedBytes).trim();
	    }
	}

	
	*/