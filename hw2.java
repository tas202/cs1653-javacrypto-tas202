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
    byte[] cipherText = AESencrypt(inputMsg, key, cipher);
    System.out.println("Encrypted input: " + cipherText.toString());
    //decrypt ciphertext
    String plainText = AESdecrypt(inputMsg.length, key, cipherText, cipher);
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
    cipherText = Blowfishencrypt(inputMsg, key, cipher);
    System.out.println("Encrypted input: " + cipherText.toString());
    //decrypt cipherText
    plainText = Blowfishdecrypt(inputMsg.length, key, cipherText, cipher);
    System.out.println("Decrypted plainText: " + plainText);
    //---------------------------------------------------------------------

    //-------------------------------RSA-----------------------------------
    //make a key pair and update cipher
    KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
    kpGen.initialize(1024);
    KeyPair kp = kpGen.generateKeyPair();
    PublicKey pubKey = kp.getPublic();
    PrivateKey privKey = kp.getPrivate();
    //System.out.println("Public Key = " + pubKey + "\nPrivateKey = " + privKey);
    cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding", "BC");


    System.out.println("\n--RSA--");
    //encrypt input message
    cipherText = RSAencrypt(inputMsg, pubKey, cipher);
    System.out.println("Encrypted input: " + cipherText.toString());
    //decrypt cipherText
    plainText = RSAdecrypt(inputMsg.length, privKey, cipherText, cipher);
    System.out.println("Decrypted plainText: " + plainText);

    //RSA Signature
    Signature sig = Signature.getInstance("SHA1withRSA", "BC");
    sig.initSign(privKey);
    sig.update(inputMsg);
    //verify the Signature
    byte[] sigBytes = sig.sign();
    sig.initVerify(kp.getPublic());
    sig.update(inputMsg);
    if(sig.verify(sigBytes)) System.out.println("Signature verification succeeded.\n");
    else System.out.println("Signature verification failed.\n");
    //---------------------------------------------------------------------


    //extra credit---------------------------------------------------------
    String[] randStrArr = generateArrOfStrings();
    /*
    for(int i = 0; i < randStrArr.length; i++){
      System.out.println((i+1) + " " + randStrArr[i]);
    } */

    //100 AES encryptions timed
    System.out.println("\nExtra Credit -- Crypto Algorithm comparisons:");
    double aes_start_time = System.nanoTime();
    cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "BC");
    for(int i = 0; i < randStrArr.length; i++){
      keyGen = KeyGenerator.getInstance("AES");
      keyGen.init(128); //128 bit key
      key = keyGen.generateKey();
      AESencrypt(randStrArr[i].getBytes(), key, cipher);
    }
    double aes_time = System.nanoTime() - aes_start_time;
    System.out.println("\t100 AES Encryptions = " + aes_time + " nanoseconds.");


    //100 Blowfish encryptions timed
    double blowfish_start_time = System.nanoTime();
    cipher = Cipher.getInstance("Blowfish/ECB/PKCS5Padding");
    for(int i = 0; i < randStrArr.length; i++){
      keyGen = KeyGenerator.getInstance("Blowfish");
      keyGen.init(128);
      key = keyGen.generateKey();
      Blowfishencrypt(randStrArr[i].getBytes(), key, cipher);
    }
    double blowfish_time = System.nanoTime() - blowfish_start_time;
    System.out.println("\t100 Blowfish Encryptions = " + blowfish_time + " nanoseconds.");

    //100 RSA encryptions timed
    double rsa_start_time = System.nanoTime();
    cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding", "BC");
    for(int i = 0; i < randStrArr.length; i++){
      kpGen = KeyPairGenerator.getInstance("RSA", "BC");
      kpGen.initialize(1024);
      kp = kpGen.generateKeyPair();
      pubKey = kp.getPublic();
      RSAencrypt(randStrArr[i].getBytes(), pubKey, cipher);
    }
    double rsa_time = System.nanoTime() - rsa_start_time;
    System.out.println("\t100 RSA Encryptions = " + rsa_time + " nanoseconds");

    //comparisons
    double aes_comp_rsa = rsa_time / aes_time;
    System.out.printf("\nAES encryption is %.2f times faster than RSA encryption.\n", aes_comp_rsa);

    double blowfish_comp_rsa = rsa_time / blowfish_time;
    System.out.printf("Blowfish encryption is %.2f times faster than RSA encryption.\n", blowfish_comp_rsa);

    double blowfish_comp_aes = aes_time / blowfish_time;
    System.out.printf("Blowfish encryption is %.2f times faster than AES encryption.\n", blowfish_comp_aes);

    //---------------------------------------------------------------------


  }

  static String[] generateArrOfStrings(){
    String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                        + "0123456789"
                        + "abcdefghijklmnopqrstuvxyz";
    StringBuilder sb = new StringBuilder();
    String[] ret = new String[100];

    for(int k = 0; k < ret.length; k++){
      for (int i = 0; i < 50; i++) {        //strings of length 40
        int index = (int)(characters.length() * Math.random());
        sb.append(characters.charAt(index));
      }
      ret[k] = sb.toString();
      sb.setLength(0); //clear the current string
    }
    return ret;
  }

  static byte[] AESencrypt(byte[] inputMsg, SecretKey key, Cipher cipher)throws Exception{
    //encrypt input message
    byte[] cipherText = new byte[inputMsg.length];
    cipher.init(Cipher.ENCRYPT_MODE, key);
    cipherText = cipher.doFinal(inputMsg);
    return cipherText;
  }
  static String AESdecrypt(int inputMsgLength, SecretKey key, byte[] cipherText, Cipher cipher)throws Exception{
    byte[] plainTextBytes = new byte[inputMsgLength];
    cipher.init(Cipher.DECRYPT_MODE, key);
    plainTextBytes = cipher.doFinal(cipherText);
    String plainText = new String(plainTextBytes); //bytes to String
    return plainText;
  }

  static byte[] Blowfishencrypt(byte[] inputMsg, SecretKey key, Cipher cipher)throws Exception{
    //encrypt input message
    byte[] cipherText = new byte[inputMsg.length];
    cipher.init(Cipher.ENCRYPT_MODE, key);
    cipherText = cipher.doFinal(inputMsg);
    return cipherText;
  }
  static String Blowfishdecrypt(int inputMsgLength, SecretKey key, byte[] cipherText, Cipher cipher)throws Exception{
    byte[] plainTextBytes = new byte[inputMsgLength];
    cipher.init(Cipher.DECRYPT_MODE, key);
    plainTextBytes = cipher.doFinal(cipherText);
    String plainText = new String(plainTextBytes); //bytes to String
    return plainText;
  }

  static byte[] RSAencrypt(byte[] inputMsg, PublicKey pubKey, Cipher cipher)throws Exception{
    //encrypt input message
    byte[] cipherText = new byte[inputMsg.length];
    cipher.init(Cipher.ENCRYPT_MODE, pubKey); //encrypt with someones public key
    cipherText = cipher.doFinal(inputMsg);
    return cipherText;
  }
  static String RSAdecrypt(int inputMsgLength, PrivateKey privKey, byte[] cipherText, Cipher cipher)throws Exception{
    byte[] plainTextBytes = new byte[inputMsgLength];
    cipher.init(Cipher.DECRYPT_MODE, privKey); //user decrypts with user's private key
    plainTextBytes = cipher.doFinal(cipherText);
    String plainText = new String(plainTextBytes);
    return plainText;
  }


}
