import javax.crypto.*;
import java.security.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.util.*;

public class hw2{
  public static void main(String[] args) throws Exception{

    Security.addProvider(new BouncyCastleProvider());

    Scanner scan = new Scanner(System.in);
    //get input message
    System.out.println("Enter line to encrypt: ");
    //this converts the input String to bytes
    byte[] inputMsg = scan.nextLine().getBytes();

    //----------------------------------AES--------------------------------
    //create key and generate cipher
    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "BC");
    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    keyGen.init(128); //128 bit key
    SecretKey key = keyGen.generateKey();


    System.out.println("\n--AES--");
    //System.out.println("128-bit AES Key: " + key.toString());
    //encrypt input message
    byte[] cipherText = new byte[inputMsg.length];
    cipher.init(Cipher.ENCRYPT_MODE, key);
    cipherText = cipher.doFinal(inputMsg);
    System.out.println("Encrypted input: " + cipherText.toString());
    //decrypt ciphertext
    byte[] plainTextBytes = new byte[inputMsg.length];
    cipher.init(Cipher.DECRYPT_MODE, key);
    plainTextBytes = cipher.doFinal(cipherText);
    String plainText = new String(plainTextBytes); //bytes to String
    System.out.println("Decrypted plainText: " + plainText);
    //---------------------------------------------------------------------

    //---------------------------------Blowfish----------------------------
    //update key and cipher for blowfish
    cipher = Cipher.getInstance("Blowfish/ECB/PKCS5Padding");
    keyGen = KeyGenerator.getInstance("Blowfish");
    keyGen.init(128);
    key = keyGen.generateKey();

    System.out.println("\n--Blowfish--");
    //System.out.println("128-bit Blowfish Key: " + key.toString());
    //encrypt input message
    cipherText = new byte[inputMsg.length];
    cipher.init(Cipher.ENCRYPT_MODE, key);
    cipherText = cipher.doFinal(inputMsg);
    System.out.println("Encrypted input: " + cipherText.toString());
    //decrypt cipherText
    plainTextBytes = new byte[inputMsg.length];
    cipher.init(Cipher.DECRYPT_MODE, key);
    plainTextBytes = cipher.doFinal(cipherText);
    plainText = new String(plainTextBytes);
    System.out.println("Decrypted plainText: " + plainText);
    //---------------------------------------------------------------------

    //-------------------------------RSA-----------------------------------
    //make a key pair and update cipher
    KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
    kpGen.initialize(1024);
    KeyPair kp = kpGen.generateKeyPair();
    Key pubKey = kp.getPublic();
    Key privKey = kp.getPrivate();
    //System.out.println("Public Key = " + pubKey + "\nPrivateKey = " + privKey);
    cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding", "BC");


    System.out.println("\n--RSA--");
    //encrypt input message
    cipherText = new byte[inputMsg.length];
    cipher.init(Cipher.ENCRYPT_MODE, pubKey); //encrypt with someones public key
    cipherText = cipher.doFinal(inputMsg);
    System.out.println("Encrypted input: " + cipherText.toString());
    //decrypt cipherText
    plainTextBytes = new byte[inputMsg.length];
    cipher.init(Cipher.DECRYPT_MODE, privKey); //user decrypts with user's private key
    plainTextBytes = cipher.doFinal(cipherText);
    plainText = new String(plainTextBytes);
    System.out.println("Decrypted plainText: " + plainText);
    //---------------------------------------------------------------------
  }
}
