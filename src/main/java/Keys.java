import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

class Keys {

  //====================================================================================
  // MAIN
  //====================================================================================
  public static void main(String[] args) throws Exception {

    //GENERATE KEY PAIR
    KeyPair keyPair = generateKeyPair();

    //GET KEYS
    PrivateKey privateKey = keyPair.getPrivate();
    PublicKey  publicKey  = keyPair.getPublic ();

    //SAVE KEYS TO FILES (as text)
    saveKeyAsText(privateKey, "PrivateKey.txt", "PRIVATE");
    saveKeyAsText(publicKey , "PublicKey.txt" , "PUBLIC" );

    //SAVE KEYS TO FILES (in binary format)
    writeBytesToFile("Private.key", privateKey.getEncoded());
    writeBytesToFile("Public.key" , publicKey .getEncoded());

    //READ KEYS FROM FILES (from binary format)
    PrivateKey privateKeyFromFile = readPrivateKeyFromFile("Private.key");
    PublicKey  publicKeyFromFile  = readPublicKeyFromFile ("Public.key");

    //DIGITAL SIGNATURE
    createDigitalSignature("Data.txt", "Signature.txt", privateKey);
    verifyDigitalSignature("Data.txt", "Signature.txt", publicKeyFromFile);

    //TEST STUFF
    writeStringToFile("First line", "Test.txt");
    String content = readStringFromFile("Test.txt");
    System.out.println(content);

  }

  //====================================================================================
  // GENERATE KEY PAIR
  //====================================================================================
  private static KeyPair generateKeyPair() throws Exception {

    //GENERATE KEY PAIR
    KeyPairGenerator  keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                      keyPairGenerator.initialize(2048);
    KeyPair           keyPair          = keyPairGenerator.generateKeyPair();
    Key               privateKey       = keyPair.getPrivate();
    Key               publicKey        = keyPair.getPublic();

    //DISPLAY FORMATS
    System.err.println("Private key format: " + privateKey.getFormat());   //PKCS#8
    System.err.println("Public  key format: " + publicKey .getFormat() );  //X.509

    //RETURN KEY PAIR
    return keyPair;

  }

  //====================================================================================
  // SAVE KEY AS TEXT
  //====================================================================================
  private static void saveKeyAsText(Key key, String fileName, String keyType) throws IOException {

    //ENCODE KEY
    Base64.Encoder encoder    = Base64.getEncoder();
    String         encodedKey = encoder.encodeToString(key.getEncoded());

    //CREATE FILE CONTENT
    String content  = "-----BEGIN RSA " + keyType + " KEY-----\n";
           content += encodedKey;
           content += "\n-----END RSA " + keyType + " KEY-----\n";

    //WRITE STRING TO FILE
    writeStringToFile(content, fileName);

  }

  //====================================================================================
  // READ PRIVATE KEY FROM FILE
  //====================================================================================
  private static PrivateKey readPrivateKeyFromFile(String fileName) throws Exception {

    //GENERATE PRIVATE KEY
    byte[]              privateKeyBytes     = readBytesFromFile(fileName);
    PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
    KeyFactory          keyFactory          = KeyFactory.getInstance("RSA");
    PrivateKey          privateKey          = keyFactory.generatePrivate(pkcs8EncodedKeySpec);

    //DISPLAY FORMAT
    System.err.println("Private key format: " + privateKey.getFormat());   //PKCS#8

    //RETURN PRIVATE KEY
    return privateKey;

  }

  //====================================================================================
  // READ PUBLIC KEY FROM FILE
  //====================================================================================
  private static PublicKey readPublicKeyFromFile(String fileName) throws Exception {

    //GENERATE PUBLIC KEY
    byte[]              publicKeyBytes      = readBytesFromFile(fileName);
    X509EncodedKeySpec  x509EncodedKeySpec  = new X509EncodedKeySpec(publicKeyBytes);
    KeyFactory          keyFactory          = KeyFactory.getInstance("RSA");
    PublicKey           publicKey           = keyFactory.generatePublic(x509EncodedKeySpec);

    //DISPLAY FORMAT
    System.err.println("Public key format: " + publicKey.getFormat());   //X509

    //RETURN PUBLIC KEY
    return publicKey;

  }

  //====================================================================================
  // CREATE DIGITAL SIGNATURE
  //====================================================================================
  private static void createDigitalSignature(String dataFile, String signatureFile, PrivateKey privateKey) throws Exception {

    //READ DATA FROM FILE
    byte[] dataBytes = readBytesFromFile(dataFile);

    //INITIALIZE SIGNATURE
    Signature signature = Signature.getInstance("SHA256withRSA");
              signature.initSign(privateKey);
              signature.update(dataBytes, 0, dataBytes.length);

    //CREATE SIGNATURE
    byte[] signatureBytes = signature.sign();

    //WRITE SIGNATURE TO FILE
    writeBytesToFile(signatureFile, signatureBytes);

  }

  //====================================================================================
  // VERIFY DIGITAL SIGNATURE
  //====================================================================================
  private static void verifyDigitalSignature(String dataFile, String signatureFile, PublicKey publicKey) throws Exception {

    //READ DATA & SIGNATURE FROM FILE
    byte[] dataBytes      = readBytesFromFile(dataFile);
    byte[] signatureBytes = readBytesFromFile(signatureFile);

    //INITIALIZE SIGNATURE
    Signature signature = Signature.getInstance("SHA256withRSA");
              signature.initVerify(publicKey);
              signature.update(dataBytes, 0, dataBytes.length);

    //VERIFY SIGNATURE
    boolean verified = signature.verify(signatureBytes);

    //DISPLAY RESULT
    System.out.println("Signature verified: " + verified);

  }

  //====================================================================================
  // READ BYTES FROM FILE
  //====================================================================================
  private static byte[] readBytesFromFile(String fileName) throws IOException {
    Path   filePath = Path.of(fileName);
    byte[] content  = Files.readAllBytes(filePath);
    return content;
  }

  //====================================================================================
  // WRITE BYTES TO FILE
  //====================================================================================
  private static void writeBytesToFile(String fileName, byte[] content) throws IOException {
    Path filePath = Path.of(fileName);
    Files.write(filePath, content);
  }

  //====================================================================================
  // WRITE STRING TO FILE
  //====================================================================================
  private static void writeStringToFile(String content, String fileName) throws IOException {
    Path filePath = Path.of(fileName);
    Files.writeString(filePath, content);
  }

  //====================================================================================
  // READ STRING FROM FILE
  //====================================================================================
  private static String readStringFromFile(String fileName) throws IOException {
    Path   filePath = Path.of(fileName);
    String content  = Files.readString(filePath);
    return content;
  }

}
