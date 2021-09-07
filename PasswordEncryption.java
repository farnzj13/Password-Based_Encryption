import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

//links used to implement this
// https://stackoverflow.com/questions/992019/java-256-bit-aes-password-based-encryption/992413#992413
// https://stackoverflow.com/questions/29354133/how-to-fix-invalid-aes-key-length/29354222
// https://howtodoinjava.com/java/java-security/aes-256-encryption-decryption/
// https://github.com/luke-park/SecureCompatibleEncryptionExamples/blob/master/Java/SCEE.java

public class Pt3FileEncryptor {

    private static final Logger LOG = Logger.getLogger(Pt3FileEncryptor.class.getSimpleName());

    private static final String ALGORITHM = "AES";
    private static final String CIPHER = "AES/CBC/PKCS5PADDING";

    //encrypt
    public static void encrypt(String inputFile, String outputFile, Path tempDir, String passwordString) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, InvalidAlgorithmParameterException, InvalidKeySpecException {

        //IV- Salt
        SecureRandom sr = new SecureRandom();
        byte[] salt = new byte[16];
        sr.nextBytes(salt);

        //Iteration count
        int count = 65536;
        char[] password = passwordString.toCharArray();

        SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec keySpec = new PBEKeySpec(password, salt, count, 256);
        SecretKey tmp = keyFac.generateSecret(keySpec);
        SecretKey secKey = new SecretKeySpec(tmp.getEncoded(), ALGORITHM);
        IvParameterSpec paramSpec = new IvParameterSpec(salt);

        //Print out secret key and IV and encode
        System.out.println("Random key " + Base64.getEncoder().encodeToString(secKey.getEncoded()));
        System.out.println("initVector " + Base64.getEncoder().encodeToString(salt));


        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, secKey, paramSpec);

        final Path encryptedPath = tempDir.resolve(outputFile);
        try (InputStream fin = Pt2FileEncryption.class.getResourceAsStream(inputFile);
             //create a file output stream
             OutputStream fout = Files.newOutputStream(encryptedPath);
             CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher) {
             }) {
            fout.write(salt);
            final byte[] bytes = new byte[1024];
            for(int length=fin.read(bytes); length!=-1; length = fin.read(bytes)){
                cipherOut.write(bytes, 0, length);
            }
        } catch (IOException e) {
            LOG.log(Level.INFO, "Unable to encrypt", e);
        }

        LOG.info("Encryption finished, saved at " + encryptedPath);

    }

    //decrypt
    public static void decrypt(String inputFile, String outputFile, Path tempDir, String passwordString)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, IOException, InvalidKeySpecException {

        //Decrypt files paths
        final byte[] initVector = new byte[16];
        int count = 65536;
        char[] password = passwordString.toCharArray();

        //Encrypted and decrypt paths
        final Path encryptedPath = tempDir.resolve(inputFile);
        final Path decryptedPath = tempDir.resolve(outputFile);


        InputStream encryptedData = Files.newInputStream(encryptedPath);
        encryptedData.read(initVector);
        //Derive key from given password and salt
        SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec keySpec = new PBEKeySpec(password, initVector, count,256);
        SecretKey tmp = keyFac.generateSecret(keySpec);
        SecretKey secKey = new SecretKeySpec(tmp.getEncoded(), ALGORITHM);
        IvParameterSpec paramSpec = new IvParameterSpec(initVector);
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, secKey, paramSpec);

        System.out.println("Random key " + Base64.getEncoder().encodeToString(secKey.getEncoded()));
        System.out.println("initVector " + Base64.getEncoder().encodeToString(initVector));


        try(CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher);
            OutputStream decryptedOut = Files.newOutputStream(decryptedPath))   {

            final byte[] bytes = new byte[1024];

            for(int length=decryptStream.read(bytes); length!=-1; length = decryptStream.read(bytes)){
                decryptedOut.write(bytes, 0, length);
            }
        } catch (IOException ex) {
            Logger.getLogger(Pt2FileEncryption.class.getName()).log(Level.SEVERE, "Unable to decrypt", ex);
        }

        LOG.info("Decryption complete, open " + decryptedPath);
    }


    public static void main(String[] args) {
        System.out.println("TEST");
        String inputFile, outputFile, passwordString;
        Path tempDir = Paths.get("");
        String enc = "enc";
        String dec = "dec";
        try{
            if (args.length >= 1) {
                if (args[0].equals(enc)) {
                    passwordString = args[1];
                    inputFile = args[2];
                    outputFile = args[3];
                    encrypt(inputFile, outputFile, tempDir, passwordString);
                }
                if (args[0].equals(dec)) {
                    passwordString = args[1];
                    inputFile = args[2];
                    outputFile = args[3];
                    decrypt(inputFile, outputFile, tempDir, passwordString);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
