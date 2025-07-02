package signaturepackage;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Base64;
public class signatureclass {
	
	

	 public static String getPrivateKey() {
	        try {
	            // Generate a key pair
	            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
	            kpg.initialize(2048);
	            KeyPair keyPair = kpg.generateKeyPair();

	            // Get the private key and return it as a Base64 encoded string
	            PrivateKey privateKey = keyPair.getPrivate();
	            return Base64.getEncoder().encodeToString(privateKey.getEncoded());
	        } catch (Exception e) {
	            // Handle exceptions and print the stack trace
	            e.printStackTrace();
	            return null; // Return null or handle it according to your application's needs
	        }
	    }

	    // Method to create a digital signature using the private key
	    public static String createSignature(String message) {
	        try {
	            // Generate a new key pair
	            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
	            kpg.initialize(2048);
	            KeyPair keyPair = kpg.generateKeyPair();
	            PrivateKey privKey = keyPair.getPrivate();

	            // Create a Signature object
	            Signature sign = Signature.getInstance("SHA256withRSA");

	            // Initialize the signature with the private key
	            sign.initSign(privKey);

	            // Update the signature with the message
	            sign.update(message.getBytes());

	            // Sign the message
	            byte[] signature = sign.sign();

	            // Return the signature in Base64 format
	            return Base64.getEncoder().encodeToString(signature);
	        } catch (Exception e) {
	            e.printStackTrace();
	            return null;
	        }
	    }
}
