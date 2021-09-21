import java.security.*;

class Main {

  //====================================================================================
  // MAIN
  //====================================================================================
  public static void main(String[] args) throws Exception {
    binary();
    text();
  }

  //====================================================================================
  // BINARY
  //====================================================================================
  public static void binary() throws Exception {

    //GENERATE KEY PAIR
    KeyPair    keyPair    = UtilKeys.generateKeyPairRSA();

    //GET KEYS
    PrivateKey privateKey = keyPair.getPrivate();
    PublicKey  publicKey  = keyPair.getPublic();

    //SAVE KEYS TO BINARY FILES
    UtilFiles.writeBytesToFile("PrivateKey.bin", privateKey.getEncoded());
    UtilFiles.writeBytesToFile("PublicKey.bin" , publicKey .getEncoded());

    //READ KEYS FROM BINARY FILES
    PrivateKey privateKeyFromBinaryFile = UtilKeys.readPrivateKeyFromBinaryFile("PrivateKey.bin", "RSA");
    PublicKey  publicKeyFromBinaryFile  = UtilKeys.readPublicKeyFromBinaryFile ("PublicKey.bin" , "RSA");

    //CREATE DIGITAL SIGNATURE
    byte[]     dataBytes      = UtilFiles.readBytesFromFile("Data.txt");
    byte[]     signatureBytes = UtilSignature.createSignature(dataBytes, "SHA256withRSA", privateKeyFromBinaryFile);
    UtilFiles.writeBytesToFile("Signature.bin", signatureBytes);

    //VALIDATE DIGITAL SIGNATURE
    byte[]     dataBytesFromFile     = UtilFiles.readBytesFromFile("Data.txt");
    byte[]     signaturBytesFromFile = UtilFiles.readBytesFromFile("Signature.bin");
    boolean    verified              = UtilSignature.verifySignature(dataBytesFromFile, signaturBytesFromFile, "SHA256withRSA", publicKeyFromBinaryFile);

  }

  //====================================================================================
  // TEXT
  //====================================================================================
  public static void text() throws Exception {

    //GENERATE KEY PAIR
    KeyPair    keyPair    = UtilKeys.generateKeyPairRSA();

    //GET KEYS
    PrivateKey privateKey = keyPair.getPrivate();
    PublicKey  publicKey  = keyPair.getPublic();

    //SAVE KEYS TO TEXT FILES
    UtilFiles.encodeBytesIntoTextFile("PrivateKey.txt", privateKey.getEncoded());
    UtilFiles.encodeBytesIntoTextFile("PublicKey.txt" , publicKey .getEncoded());

    //READ KEYS FROM TEXT FILES
    PrivateKey privateKeyFromTextFile = UtilKeys.readPrivateKeyFromTextFile("PrivateKey.txt", "RSA");
    PublicKey  publicKeyFromTextFile  = UtilKeys.readPublicKeyFromTextFile ("PublicKey.txt" , "RSA");

    //CREATE DIGITAL SIGNATURE
    byte[]     dataBytes     = UtilFiles.readBytesFromFile("Data.txt");
    byte[]     signaturBytes = UtilSignature.createSignature(dataBytes, "SHA256withRSA", privateKeyFromTextFile);
    UtilFiles.encodeBytesIntoTextFile("Signature.txt", signaturBytes);

    //VALIDATE DIGITAL SIGNATURE
    byte[]     dataBytesFromFile     = UtilFiles.readBytesFromFile("Data.txt");
    byte[]     signaturBytesFromFile = UtilFiles.decodeTextFileIntoBytes("Signature.txt");
    boolean    verified              = UtilSignature.verifySignature(dataBytesFromFile, signaturBytesFromFile, "SHA256withRSA", publicKeyFromTextFile);

  }

}
