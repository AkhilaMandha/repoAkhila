package algoencryptpadding;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Scanner;
import java.util.Arrays;

public class AesCbcNoPadding {

	

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
	        System.out.println("Enter the padding mode (NoPadding):");
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
	            TRANSFORMATION = algorithm + "/" + encmode + "/" + padding;

	            // Encrypt the input
	            String encryptedText = encrypt(input, secretKey);
	            System.out.println("Encrypted Text: " + encryptedText);

	            // Decrypt the encrypted text
	            String decryptedText = decrypt(encryptedText, secretKey);
	            System.out.println("Decrypted Text: " + decryptedText);

	            // Return both encrypted and decrypted texts
	            return "{ \"Encrypted Data\": \"" + encryptedText + "\", \"Decrypted Data\": \"" + decryptedText + "\" }";
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

	        // Handle NoPadding specifically by padding manually to a multiple of 16 bytes
	        byte[] inputBytes = input.getBytes();
	        int blockSize = 16;
	        int paddedLength = ((inputBytes.length + blockSize - 1) / blockSize) * blockSize;
	        byte[] paddedInput = Arrays.copyOf(inputBytes, paddedLength);

	        cipher.init(Cipher.ENCRYPT_MODE, key);
	        byte[] encryptedBytes = cipher.doFinal(paddedInput);
	        return Base64.getEncoder().encodeToString(encryptedBytes);
	    }

	    private static String decrypt(String input, SecretKey key) throws Exception {
	        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
	        cipher.init(Cipher.DECRYPT_MODE, key);
	        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(input));
	        
	        // Convert decrypted bytes back to string and trim any extra padding
	        return new String(decryptedBytes).trim();
	    }
	}


