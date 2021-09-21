import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

public class UtilSignature {

  //====================================================================================
  // CREATE SIGNATURE
  //====================================================================================
  // UtilSignature.createSignature("Data.txt", "Signature.txt", "SHA256withRSA", privateKey);
  static byte[] createSignature(
    byte[]     data,
    String     format,         //"SHA1withDSA", "SHA256withRSA"
    PrivateKey privateKey
  ) throws Exception {

    //INITIALIZE SIGNATURE
    Signature  signature = Signature.getInstance(format);
               signature.initSign(privateKey);
               signature.update(data, 0, data.length);

    //CREATE SIGNATURE
    byte[]     signatureBytes = signature.sign();

    //RETURN SIGNATURE
    return signatureBytes;

  }

  //====================================================================================
  // VERIFY SIGNATURE
  //====================================================================================
  // UtilSignature.verifySignature("Data.txt", "Signature.txt", "SHA256withRSA", publicKeyFromFile);
  static boolean verifySignature(
    byte[]    dataBytes,
    byte[]    signatureBytes,
    String    format,          //"SHA1withDSA", "SHA256withRSA"
    PublicKey publicKey
  ) throws Exception {

    //INITIALIZE SIGNATURE
    Signature signature = Signature.getInstance(format);
              signature.initVerify(publicKey);
              signature.update(dataBytes, 0, dataBytes.length);

    //VERIFY SIGNATURE
    boolean   verified = signature.verify(signatureBytes);

    //DISPLAY RESULT
    System.out.println("Signature verified: " + verified);

    //RETURN RESULT
    return verified;

  }

  //====================================================================================
  // SAVE SIGNATURE AS TEXT FILE
  //====================================================================================
  // UtilSignature.saveSignatureAsTextFile(privateKey, "PrivateKey.txt");
  static void saveSignatureAsTextFile(
    String fileName,
    byte[] signatureBytes
  ) throws IOException {

    //ENCODE SIGNATURE
    Base64.Encoder encoder         = Base64.getEncoder();
    String         singatureString = encoder.encodeToString(signatureBytes);

    //WRITE SIGNATURE TO TEXT FILE
    UtilFiles.writeStringToFile(fileName, singatureString);

  }

}
