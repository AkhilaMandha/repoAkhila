package encryptsharedkeypackage;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;

public class encryptsharedkeyclass {
	


	
	   //ublic static void main(String[] args) {
	        // Specify file paths for private and public keys
	      //String privateKeyPath = "D:\\cryptographytask\\privatekeyflow1.pem"; // Change the path as needed
	      //String publicKeyPath = "D:\\cryptographytask\\publickeyflow1.pem"; // Change the path as needed

	      

	            public static String generateAndSaveKeyPair(String privateKeyPath, String publicKeyPath) {
	                try {
	                    // Step 1: Create a KeyPairGenerator instance for RSA
	                    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");

	                    // Step 2: Initialize the KeyPairGenerator with a key size of 2048 bits
	                    keyPairGenerator.initialize(2048, new SecureRandom());

	                    // Step 3: Generate the Key Pair
	                    KeyPair keyPair = keyPairGenerator.generateKeyPair();

	                    // Step 4: Extract the Private Key
	                    PrivateKey privateKey = keyPair.getPrivate();
	                    String privateKeyPEM = convertToPEM(privateKey.getEncoded(), "PRIVATE");
	                    writeToFile(privateKeyPath, privateKeyPEM);

	                    // Step 5: Extract the Public Key
	                    PublicKey publicKey = keyPair.getPublic();
	                    String publicKeyPEM = convertToPEM(publicKey.getEncoded(), "PUBLIC");
	                    writeToFile(publicKeyPath, publicKeyPEM);

	                    // Return confirmation message with file paths
	                    return "Keys saved successfully:\nPrivate key path: " + privateKeyPath + "\nPublic key path: " + publicKeyPath;

	                } catch (NoSuchAlgorithmException | IOException e) {
	                    e.printStackTrace();
	                    return "Error occurred: " + e.getMessage();
	                }
	            }

	            
	            
	           

	                // Method to encrypt the shared key using Flow2's public key
	                public static String encryptSharedKeyWithPublicKey(String info12,String publicKeyBase64) {
	                    try {
	                        // Decode the Base64 encoded public key
	                        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBase64);
	                        
	                        // Generate PublicKey object from bytes
	                        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
	                        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	                        PublicKey publicKey = keyFactory.generatePublic(keySpec);

	                        // Encrypt the shared key
	                        Cipher cipher = Cipher.getInstance("RSA");
	                        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

	                        byte[] encryptedKeyBytes = cipher.doFinal(info12.getBytes());

	                        // Return the encrypted shared key as a Base64 encoded string
	                        return Base64.getEncoder().encodeToString(encryptedKeyBytes);

	                    } catch (Exception e) {
	                        e.printStackTrace();
	                        return null;  // Handle exceptions as needed
	                    }
	                }
	            

	            private static String convertToPEM(byte[] key, String keyType) {
	                // Base64 encode the key
	                StringBuilder sb = new StringBuilder();
	                sb.append("-----BEGIN ").append(keyType).append(" KEY-----\n");
	                String base64Key = Base64.getEncoder().encodeToString(key);
	                
	                // Wrap the Base64 encoded key in lines of 64 characters
	                for (int i = 0; i < base64Key.length(); i += 64) {
	                    int end = Math.min(i + 64, base64Key.length());
	                    sb.append(base64Key, i, end).append("\n");
	                }
	                sb.append("-----END ").append(keyType).append(" KEY-----");
	                return sb.toString();
	            }

	            private static void writeToFile(String filePath, String data) throws IOException {
	                try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath))) {
	                    writer.write(data);
	                }
	            }
	        }

	  /*  public static void main(String[] args) {
	        // Generate the public key
	        String publicKey = getPublicKey();
	        System.out.println("Generated Public Key (Base64): " + publicKey);

	        // Generate the shared secret key
	        String sharedKey = getSecretKey();
	        System.out.println("Generated Shared Key (Base64): " + sharedKey);

	        // Encrypt the shared key using the public key
	        String encryptedSharedKey = encryptSharedKey(sharedKey, publicKey);
	        System.out.println("Encrypted Shared Key (Base64): " + encryptedSharedKey);
	    }  */
	



