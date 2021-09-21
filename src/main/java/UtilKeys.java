import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class UtilKeys {

  //====================================================================================
  // GENERATE KEY PAIR RSA
  //====================================================================================
  // KeyPair             keyPair    = UtilKeys.generateKeyPairRSA();
  // PrivateKey          privateKey = keyPair.getPrivate();
  // PublicKey           publicKey  = keyPair.getPublic();
  // System.err.println("Private key format: " + privateKey.getFormat());   //PKCS#8
  // System.err.println("Public  key format: " + publicKey .getFormat() );  //X.509
  static KeyPair generateKeyPairRSA() throws Exception {

    //GENERATE KEY PAIR
    KeyPairGenerator  keyPairGenerator  = KeyPairGenerator.getInstance("RSA");
                      keyPairGenerator.initialize(2048);
    KeyPair           keyPair          = keyPairGenerator.generateKeyPair();

    //RETURN KEY PAIR
    return keyPair;

  }

  //====================================================================================
  // GENERATE KEY PAIR DSA
  //====================================================================================
  // KeyPair             keyPair    = UtilKeys.generateKeyPairDSA();
  // PrivateKey          privateKey = keyPair.getPrivate();
  // PublicKey           publicKey  = keyPair.getPublic();
  // System.err.println("Private key format: " + privateKey.getFormat());   //PKCS#8
  // System.err.println("Public  key format: " + publicKey .getFormat() );  //X.509
  static KeyPair generateKeyPairDSA() throws Exception {

    //GENERATE KEY PAIR
    SecureRandom        random     = SecureRandom.getInstance("SHA1PRNG", "SUN");
    KeyPairGenerator    keyGen     = KeyPairGenerator.getInstance("DSA", "SUN");
                        keyGen.initialize(1024, random);
    KeyPair             keyPair    = keyGen.generateKeyPair();

    //RETURN KEY PAIR
    return keyPair;

  }

  //====================================================================================
  // READ PRIVATE KEY FROM TEXT FILE
  //====================================================================================
  // UtilKeys.readPrivateKeyFromTextFile("PrivateKey.txt", "RSA");
  static PrivateKey readPrivateKeyFromTextFile(
    String fileName,
    String format
  ) throws Exception {

    //READ PRIVATE KEY FROM TEXT FILE
    byte[]              privateKeyBytes     = UtilFiles.decodeTextFileIntoBytes(fileName);

    //GENERATE PRIVATE KEY
    PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
    KeyFactory          keyFactory          = KeyFactory.getInstance(format);
    PrivateKey          privateKey          = keyFactory.generatePrivate(pkcs8EncodedKeySpec);

    //DISPLAY FORMAT
    System.out.println("Private key format: " + privateKey.getFormat());   //PKCS#8

    //RETURN KEY
    return privateKey;

  }

  //====================================================================================
  // READ PUBLIC KEY FROM TEXT FILE
  //====================================================================================
  // UtilKeys.readPrivateKeyFromTextFile("PrivateKey.txt", "RSA");
  static PublicKey readPublicKeyFromTextFile(
    String fileName,
    String format
  ) throws Exception {

    //READ PUBLIC KEY FROM TEXT FILE
    byte[]              publicKeyBytes     = UtilFiles.decodeTextFileIntoBytes(fileName);

    //GENERATE PRIVATE KEY
    X509EncodedKeySpec  x509EncodedKeySpec = new X509EncodedKeySpec(publicKeyBytes);
    KeyFactory          keyFactory         = KeyFactory.getInstance(format);
    PublicKey           publicKey          = keyFactory.generatePublic(x509EncodedKeySpec);

    //DISPLAY FORMAT
    System.out.println("Public key format: " + publicKey.getFormat());   //PKCS#8

    //RETURN KEY
    return publicKey;

  }

  //====================================================================================
  // READ PRIVATE KEY FROM BINARY FILE
  //====================================================================================
  // PrivateKey privateKeyFromFile = UtilKeys.readPrivateKeyFromFile("Private.key", "RSA");
  static PrivateKey readPrivateKeyFromBinaryFile(
    String fileName,
    String format       //"RSA", "DSA"
  ) throws Exception {

    //READ PRIVATE KEY FROM BINARY FILE
    byte[]              privateKeyBytes     = UtilFiles.readBytesFromFile(fileName);

    //GENERATE PRIVATE KEY
    PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
    KeyFactory          keyFactory          = KeyFactory.getInstance(format);
    PrivateKey          privateKey          = keyFactory.generatePrivate(pkcs8EncodedKeySpec);

    //DISPLAY FORMAT
    System.out.println("Private key format: " + privateKey.getFormat());   //PKCS#8

    //RETURN PRIVATE KEY
    return privateKey;

  }

  //====================================================================================
  // READ PUBLIC KEY FROM BINARY FILE
  //====================================================================================
  // PublicKey publicKeyFromFile  = UtilKeys.readPublicKeyFromFile ("Public.key", "RSA");
  static PublicKey readPublicKeyFromBinaryFile(
    String fileName,
    String format       //"RSA", "DSA"
  ) throws Exception {

    //GENERATE PUBLIC KEY
    byte[]              publicKeyBytes      = UtilFiles.readBytesFromFile(fileName);

    //GENERATE PUBLIC KEY
    X509EncodedKeySpec  x509EncodedKeySpec  = new X509EncodedKeySpec(publicKeyBytes);
    KeyFactory          keyFactory          = KeyFactory.getInstance(format);
    PublicKey           publicKey           = keyFactory.generatePublic(x509EncodedKeySpec);

    //DISPLAY FORMAT
    System.out.println("Public  key format: " + publicKey.getFormat());   //X509

    //RETURN PUBLIC KEY
    return publicKey;

  }

}
