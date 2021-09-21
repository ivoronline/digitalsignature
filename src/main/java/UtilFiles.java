import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

public class UtilFiles {

  //====================================================================================
  // READ BYTES FROM FILE
  //====================================================================================
  // byte[] dataBytes = UtilFiles.readBytesFromFile(dataFile);
  static byte[] readBytesFromFile(String fileName) throws IOException {
    Path   filePath = Path.of(fileName);
    byte[] content  = Files.readAllBytes(filePath);
    return content;
  }

  //====================================================================================
  // WRITE BYTES TO FILE
  //====================================================================================
  // UtilFiles.writeBytesToFile("Private.key", privateKey.getEncoded());
  static void writeBytesToFile(String fileName, byte[] content) throws IOException {
    Path filePath = Path.of(fileName);
    Files.write(filePath, content);
  }

  //====================================================================================
  // WRITE STRING TO FILE
  //====================================================================================
  // UtilFiles.writeStringToFile("First Line", "Test.txt");
  static void writeStringToFile(String fileName, String content) throws IOException {
    Path filePath = Path.of(fileName);
    Files.writeString(filePath, content);
  }

  //====================================================================================
  // READ STRING FROM FILE
  //====================================================================================
  // String content = UtilFiles.readStringFromFile("Test.txt");
  static String readStringFromFile(String fileName) throws IOException {
    Path   filePath = Path.of(fileName);
    String content  = Files.readString(filePath);
    return content;
  }

  //====================================================================================
  // ENCODE BYTES INTO TEXT FILE
  //====================================================================================
  // UtilFiles.encodeBytesIntoTextFile("Signature.txt", byte[] content);
  static void encodeBytesIntoTextFile(String fileName, byte[] content) throws IOException {

    //CONVERT BYTES TO STRING
    Base64.Encoder encoder       = Base64.getEncoder();
    String         contentString = encoder.encodeToString(content);

    //WRITE STRING TO TEXT FILE
    UtilFiles.writeStringToFile(fileName, contentString);

  }

  //====================================================================================
  // DECODE TEXT FILE INTO BYTES
  //====================================================================================
  // UtilFiles.decodeTextFileIntoBytes("Signature.txt");
  static byte[] decodeTextFileIntoBytes(String fileName) throws IOException {

    //READ SIGNATURE KEY FROM FILE
    String         string  = UtilFiles.readStringFromFile(fileName);

    //CONVERT TEXT TO BINARY
    Base64.Decoder decoder = Base64.getDecoder();
    byte[]         bytes   = decoder.decode(string);

    //RETURN SIGNATURE
    return bytes;

  }

}
