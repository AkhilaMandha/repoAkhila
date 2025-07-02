package algoencryptpadding;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import java.util.Scanner;
import java.util.Map;

import java.nio.charset.StandardCharsets;
public class AesCbcPkcs5 {
       
	
	    private static String TRANSFORMATION = "";

	    public static void main(String[] args) {
	        Scanner sc = new Scanner(System.in);

	        // Collect input from the user
	        System.out.println("Enter the input text:");
	        String input = sc.nextLine();
	        System.out.println("Enter the algorithm (AES):");
	        String algorithm = sc.nextLine();
	        System.out.println("Enter the encryption mode (e.g., ECB, CBC):");
	        String encmode = sc.nextLine();
	        System.out.println("Enter the padding mode (PKCS5 or NoPadding):");
	        String padding = sc.nextLine();

	        // Run encryption and decryption
	        String result = returningEncryptedAndDecryptedText(input, algorithm, encmode, padding);
	        System.out.println(result);
	    }

	    public static String returningEncryptedAndDecryptedText(String input, String algorithm, String encmode, String padding) {
	        try {
	            // Generate AES key
	            SecretKey secretKey = generateAESKey();

	            // Set transformation string based on user input
	            TRANSFORMATION = algorithm + "/" + encmode + "/" + padding + "Padding";

	            // Encrypt the input
	            String encryptedText = encrypt(input, secretKey);
	            System.out.println("Encrypted Text: " + encryptedText);

	            // Decrypt the encrypted text
	            String decryptedText = decrypt(encryptedText, secretKey);
	            System.out.println("Decrypted Text: " + decryptedText);

	            // Return both encrypted and decrypted texts
	            return "{ \"Encrypted Data\": \"" + encryptedText + "\", \"Decrypted Data\": \"" + decryptedText + "\"\n}";
	        } catch (Exception e) {
	            e.printStackTrace();
	            return "Error during encryption/decryption";
	        }
	    }

	    private static SecretKey generateAESKey() throws Exception {
	        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
	        keyGen.init(128); // AES key size
	        return keyGen.generateKey();
	    }

	    private static String encrypt(String input, SecretKey key) throws Exception {
	        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
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
	}

	
	
	
	
	/*

	    private static final String AES_ALGORITHM = "AES";
	    private static final String RSA_ALGORITHM = "RSA";
	    private static String TRANSFORMATION = "";

	    public static void main(String[] args) {
	        Scanner sc = new Scanner(System.in);
	        String privateKey = "D:\\cryptographytask\\privatekeyflow1.pem"; // Change the path as needed
	        String publicKey = "D:\\cryptographytask\\publickeyflow1.pem";
	        // Collect input from the user
	        System.out.println("Enter the input text:");
	        String input = sc.nextLine();
	        System.out.println("Enter the algorithm (AES):");
	        String algorithm = sc.nextLine();
	        System.out.println("Enter the encryption mode (e.g., ECB, CBC):");
	        String encmode = sc.nextLine();
	        System.out.println("Enter the padding mode (PKCS5 or NoPadding):");
	        String padding = sc.nextLine();

	        // Generate RSA key pair
	        try {
	            KeyPair keyPair = generateRSAKeyPair();
	            PublicKey publicKey1 = keyPair.getPublic();
	            PrivateKey privateKey1 = keyPair.getPrivate();

	            // Encrypt and decrypt the input
	            String result = returningDecryptedText(input, algorithm, encmode, padding, publicKey1, privateKey1);
	            if (!result.isEmpty()) {
	                System.out.println("Final Decrypted Text: " + result);
	            }
	        } catch (Exception e) {
	            e.printStackTrace();
	        }
	    }

	    public static String returningDecryptedText(String input, String algorithm, String encmode, String padding, PublicKey publicKey, PrivateKey privateKey) {
	        try {
	            // Generate a random AES key
	            SecretKey aesKey = generateAESKey();

	            // Set transformation string based on user input
	            if (padding.equalsIgnoreCase("PKCS5") || padding.equalsIgnoreCase("NoPadding")) {
	                TRANSFORMATION = algorithm + "/" + encmode + "/" + padding + "Padding";
	            } else {
	                System.out.println("Invalid padding. Please enter 'PKCS5' or 'NoPadding'.");
	                return "";
	            }

	            // Encrypt AES key using RSA public key
	            String encryptedAESKey = encryptAESKeyWithRSA(aesKey, publicKey);
	            System.out.println("Encrypted AES Key: " + encryptedAESKey);

	            // Encrypt data using AES key
	            String encryptedText = encrypt(input, aesKey);
	            System.out.println("Encrypted Text: " + encryptedText);

	            // Decrypt AES key using RSA private key
	            SecretKey decryptedAESKey = decryptAESKeyWithRSA(encryptedAESKey, privateKey);

	            // Decrypt data using the decrypted AES key
	            String decryptedText = decrypt(encryptedText, decryptedAESKey);
	            System.out.println("Decrypted Text: " + decryptedText);
	            return decryptedText;
	        } catch (Exception e) {
	            e.printStackTrace();
	            return "Error during encryption/decryption";
	        }
	    }

	    private static KeyPair generateRSAKeyPair() throws Exception {
	        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA_ALGORITHM);
	        keyGen.initialize(2048); // Key size for RSA
	        return keyGen.generateKeyPair();
	    }

	    private static SecretKey generateAESKey() throws Exception {
	        KeyGenerator keyGen = KeyGenerator.getInstance(AES_ALGORITHM);
	        keyGen.init(128); // AES key size
	        return keyGen.generateKey();
	    }

	    private static String encryptAESKeyWithRSA(SecretKey aesKey, PublicKey publicKey) throws Exception {
	        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
	        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
	        byte[] encryptedKeyBytes = cipher.doFinal(aesKey.getEncoded());
	        return Base64.getEncoder().encodeToString(encryptedKeyBytes);
	    }

	    private static SecretKey decryptAESKeyWithRSA(String encryptedAESKey, PrivateKey privateKey) throws Exception {
	        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
	        cipher.init(Cipher.DECRYPT_MODE, privateKey);
	        byte[] decryptedKeyBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedAESKey));
	        return new SecretKeySpec(decryptedKeyBytes, AES_ALGORITHM);
	    }

	    private static String encrypt(String input, SecretKey key) throws Exception {
	        Cipher cipher = Cipher.getInstance(TRANSFORMATION);

	        if (TRANSFORMATION.endsWith("NoPadding")) {
	            byte[] inputBytes = input.getBytes();
	            int blockSize = 16; // AES block size
	            int paddedLength = ((inputBytes.length + blockSize - 1) / blockSize) * blockSize;
	            byte[] paddedInput = new byte[paddedLength];
	            System.arraycopy(inputBytes, 0, paddedInput, 0, inputBytes.length);

	            cipher.init(Cipher.ENCRYPT_MODE, key);
	            byte[] encryptedBytes = cipher.doFinal(paddedInput);
	            return Base64.getEncoder().encodeToString(encryptedBytes);
	        } else {
	            cipher.init(Cipher.ENCRYPT_MODE, key);
	            byte[] encryptedBytes = cipher.doFinal(input.getBytes());
	            return Base64.getEncoder().encodeToString(encryptedBytes);
	        }
	    }

	    private static String decrypt(String input, SecretKey key) throws Exception {
	        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
	        cipher.init(Cipher.DECRYPT_MODE, key);
	        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(input));
	        return new String(decryptedBytes).trim(); // Trim in case of padding
	    }
	}

	
	
	
	/*

	    private static final String ALGORITHM = "AES";
	    private static String TRANSFORMATION = "";

	    public static void main(String[] args) {
	        Scanner sc = new Scanner(System.in);

	        // Collect input from the user
	        System.out.println("Enter the input text:");
	        String input = sc.nextLine();
	        System.out.println("Enter the algorithm (AES):");
	        String algorithm = sc.nextLine();
	        System.out.println("Enter the encryption mode (e.g., ECB, CBC):");
	        String encmode = sc.nextLine();
	        System.out.println("Enter the padding mode (PKCS5 or NoPadding):");
	        String padding = sc.nextLine();

	        // Run encryption and decryption
	        String result = returningDecryptedText(input, algorithm, encmode, padding);
	        if (!result.isEmpty()) {
	            System.out.println("Final Decrypted Text: " + result);
	        }
	    }

	    public static String returningDecryptedText(String input, String algorithm, String encmode, String padding) {
	        try {
	            // Generate a random AES key
	            SecretKey secretKey = generateAESKey();

	            // Set transformation string based on user input
	            if (padding.equalsIgnoreCase("PKCS5") || padding.equalsIgnoreCase("NoPadding")) {
	                TRANSFORMATION = algorithm + "/" + encmode + "/" + padding + "Padding";
	            } else {
	                System.out.println("Invalid padding. Please enter 'PKCS5' or 'NoPadding'.");
	                return "";
	            }

	            // Encrypt and decrypt the input
	            String encryptedText = encrypt(input, secretKey);
	            System.out.println("Encrypted Text: " + encryptedText);

	            String decryptedText = decrypt(encryptedText, secretKey);
	            System.out.println("Decrypted Text: " + decryptedText);
	            return decryptedText;
	        } catch (Exception e) {
	            e.printStackTrace();
	            return "Error during encryption/decryption";
	        }
	    }

	    private static SecretKey generateAESKey() throws Exception {
	        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
	        keyGen.init(128); // AES key size
	        return keyGen.generateKey();
	    }

	    private static String encrypt(String input, SecretKey key) throws Exception {
	        Cipher cipher = Cipher.getInstance(TRANSFORMATION);

	        if (TRANSFORMATION.endsWith("NoPadding")) {
	            byte[] inputBytes = input.getBytes();
	            int blockSize = 16; // AES block size
	            int paddedLength = ((inputBytes.length + blockSize - 1) / blockSize) * blockSize;
	            byte[] paddedInput = new byte[paddedLength];
	            System.arraycopy(inputBytes, 0, paddedInput, 0, inputBytes.length);

	            cipher.init(Cipher.ENCRYPT_MODE, key);
	            byte[] encryptedBytes = cipher.doFinal(paddedInput);
	            return Base64.getEncoder().encodeToString(encryptedBytes);
	        } else {
	            cipher.init(Cipher.ENCRYPT_MODE, key);
	            byte[] encryptedBytes = cipher.doFinal(input.getBytes());
	            return Base64.getEncoder().encodeToString(encryptedBytes);
	        }
	    }

	    private static String decrypt(String input, SecretKey key) throws Exception {
	        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
	        cipher.init(Cipher.DECRYPT_MODE, key);
	        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(input));
	        return new String(decryptedBytes).trim(); // Trim in case of padding
	    }
	}

	   /* public static String performEncryptionDecryption(Map<String, String> params) {
	        try {
	            // Retrieve parameters from the input map
	            String originalData = params.get("input");
	            String alg = params.get("alg");
	            String ecmode = params.get("ecmode");
	            String padding = params.get("padding");

	            // Generate AES key
	            KeyGenerator keyGen = KeyGenerator.getInstance(alg);
	            keyGen.init(128); // AES key size of 128 bits
	            SecretKey aesKey = keyGen.generateKey();

	            // Set up cipher for encryption
	            String transformation = alg + "/" + ecmode + "/" + padding;
	            Cipher aesCipher = Cipher.getInstance(transformation);
	            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);

	            // Encrypt the data
	            byte[] encryptedDataBytes = aesCipher.doFinal(originalData.getBytes());
	            String encryptedDataBase64 = Base64.getEncoder().encodeToString(encryptedDataBytes);

	            // Set up cipher for decryption
	            aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
	            byte[] decryptedDataBytes = aesCipher.doFinal(Base64.getDecoder().decode(encryptedDataBase64));
	            String decryptedData = new String(decryptedDataBytes);

	            // Return encryption and decryption details
	            return "Encrypted Data (Base64): " + encryptedDataBase64 + "\n" +
	                   "Decrypted Data: " + decryptedData;

	        } catch (Exception e) {
	            e.printStackTrace();
	            return "Error during encryption/decryption";
	        }
	    }

	    public static void main(String[] args) {
	        // Example dynamic input that might come from JSON data
	        Map<String, String> inputParams = Map.of(
	                "input", "akhila",
	                "alg", "AES",
	                "ecmode", "ECB",
	                "padding", "PKCS5Padding"
	        );

	        // Perform encryption and decryption with dynamic input
	        String result = performEncryptionDecryption(inputParams);
	        System.out.println(result);
	    }
	}

	
	
	
	/*	    
	    public static String performEncryptionDecryption(String originalData, String alg, String ecmode, String padding) {
	        try {
	            // Generate AES key
	            KeyGenerator keyGen = KeyGenerator.getInstance(alg);
	            keyGen.init(128); // AES key size of 128 bits
	            SecretKey aesKey = keyGen.generateKey();

	            // Set up cipher for encryption
	            String transformation = alg + "/" + ecmode + "/" + padding;
	            Cipher aesCipher = Cipher.getInstance(transformation);
	            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);

	            // Encrypt the data
	            byte[] encryptedDataBytes = aesCipher.doFinal(originalData.getBytes());
	            String encryptedDataBase64 = Base64.getEncoder().encodeToString(encryptedDataBytes);

	            // Set up cipher for decryption
	            aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
	            byte[] decryptedDataBytes = aesCipher.doFinal(Base64.getDecoder().decode(encryptedDataBase64));
	            String decryptedData = new String(decryptedDataBytes);

	            // Return encryption and decryption details
	            return "Encrypted Data (Base64): " + encryptedDataBase64 + "\n" +
	                   "Decrypted Data: " + decryptedData;

	        } catch (Exception e) {
	            e.printStackTrace();
	            return "Error during encryption/decryption";
	        }
	    }

	    public static void main(String[] args) {
	        // Input data as provided in the JSON
	        String input = "akhila";
	        String alg = "AES";
	        String ecmode = "ECB";
	        String padding = "PKCS5Padding";

	        // Perform encryption and decryption
	        String result = performEncryptionDecryption(input, alg, ecmode, padding);
	        System.out.println(result);
	    }
	}
	
	/*	
		private static final String ALGORITHM = "AES";
	    private static String TRANSFORMATION = "";

	    public static void main(String[] args)
	    {
	    	Scanner sc=new Scanner(System.in);
	    	System.out.println("enter the input");
	    	String input=sc.nextLine();
	    	System.out.println("entre the algorithm");
	    	String algorithum=sc.nextLine();
	    	System.out.println("enter the encryption mode");
	    	String encmode=sc.nextLine();
	    	System.out.println("enter the padding mode");
	    	String padding=sc.nextLine();
	    	String result=returningdecryptedtext(input, algorithum, encmode, padding);
	    	System.out.println(result);
	            }
	    public static String returningdecryptedtext(String input,String alogrithum,String enmode,String padding)
	    {
	    	try {
	            // Generate a random AES key
	            SecretKey secretKey = generateAESKey();

	            Scanner scanner = new Scanner(System.in);
	            

	            // Set the transformation based on user input
	            if (padding.equalsIgnoreCase("PKCS5")) {
	                TRANSFORMATION = alogrithum + "/" + enmode + "/PKCS5Padding";
	            } else if (padding.equalsIgnoreCase("NoPadding")) {
	                TRANSFORMATION = alogrithum + "/" + enmode + "/NoPadding";
	            } else {
	                System.out.println("Invalid padding. Please enter 'PKCS5' or 'NoPadding'.");
	                
	            }

	         
	            String encryptedText = encrypt(input, secretKey);
	            System.out.println("Encrypted Text: " + encryptedText);

	            String decryptedText = decrypt(encryptedText, secretKey);
	            System.out.println("Decrypted Text: " + decryptedText);
	            return decryptedText;
	        } catch (Exception e) {
	            e.printStackTrace();
	        }
	    	return "";
	    }

	    private static SecretKey generateAESKey() throws Exception {
	        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
	        keyGen.init(256); // You can choose 192 or 256 bits as needed
	        return keyGen.generateKey();
	    }

	    private static String encrypt(String input, SecretKey key) throws Exception {
	        // Handle NoPadding specifically
	        if (TRANSFORMATION.endsWith("NoPadding")) {
	            // Ensure the input length is a multiple of the block size (16 bytes for AES)
	            byte[] inputBytes = input.getBytes();
	            int blockSize = 16; // AES block size
	            int paddedLength = ((inputBytes.length + blockSize - 1) / blockSize) * blockSize;
	            byte[] paddedInput = new byte[paddedLength];
	            System.arraycopy(inputBytes, 0, paddedInput, 0, inputBytes.length);

	            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
	            cipher.init(Cipher.ENCRYPT_MODE, key);
	            byte[] encryptedBytes = cipher.doFinal(paddedInput);
	            return Base64.getEncoder().encodeToString(encryptedBytes);
	        } else {
	            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
	            cipher.init(Cipher.ENCRYPT_MODE, key);
	            byte[] encryptedBytes = cipher.doFinal(input.getBytes());
	            return Base64.getEncoder().encodeToString(encryptedBytes);
	        }
	    }

	    private static String decrypt(String input, SecretKey key) throws Exception {
	        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
	        cipher.init(Cipher.DECRYPT_MODE, key);
	        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(input));
	        return new String(decryptedBytes).trim(); // Trim in case of padding
	    }	    }
		
*/
