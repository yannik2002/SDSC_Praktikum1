package helper;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

import static org.bouncycastle.util.encoders.Base64.toBase64String;

public class helper {
    public static void main(String[] args) throws CMSException, IOException, CertificateException,
            NoSuchProviderException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, OperatorCreationException {
        int choice = 0;

        Security.addProvider(new BouncyCastleProvider());

        char[] keystorePassword = "IchBinNeu0".toCharArray();
        char[] keyPassword = "IchBinNeu0".toCharArray();
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509", "BC");
        X509Certificate cryptoCertificate = (X509Certificate) certFactory
                .generateCertificate(new FileInputStream("Praktikum1/src/main/java/certs/FH.cer"));

        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(new FileInputStream("Praktikum1/src/main/java/certs/FH.p12"), keystorePassword);
        PrivateKey privateKey = (PrivateKey) keystore.getKey("FH", keyPassword);

        // Einbinden von meinem eigenen Cert
        char[] myOwnKeyStorePassword = "password".toCharArray();
        char[] myOwnKeyPassword = "password".toCharArray();
        X509Certificate myOwnCertificate = (X509Certificate) certFactory
                .generateCertificate(new FileInputStream("Praktikum1/src/main/java/certs/myOwnCert.cer"));
        KeyStore myKeyStore = KeyStore.getInstance("PKCS12");
        myKeyStore.load(new FileInputStream("Praktikum1/src/main/java/certs/myOwnKeyStore.p12"), myOwnKeyStorePassword);
        PrivateKey myOwnPrivateKey = (PrivateKey) myKeyStore.getKey("myOwn", myOwnKeyPassword);

        do {
            System.out.println("How can I help? ");
            System.out.println("0) Exit program");
            System.out.println("1) Encrypt a message");
            System.out.println("2) Encrypt a message with PSK");
            System.out.println("3) Decode a base64-encoded message");
            System.out.println("4) Decode a hex-encoded message");
            System.out.println("5) Hashing");
            System.out.println("6) Add two comma-separated numbers");
            System.out.println("7) Show certificate details of hex-encoded signed message");
            System.out.println("8) Verify signature of hex-encoded message");
            Scanner scanner = new Scanner(System.in);
            choice = Integer.parseInt(scanner.nextLine());
            if (choice < 0 || choice > 8) {
                System.out.println("Please choose a valid entry!");
            } else {
                BigInteger result = new BigInteger("0");
                BigInteger sum = new BigInteger("0");
                byte[] encryptedResponse = null;
                byte[] decryptedRawChallenge = null;
                byte[] response = null;
                byte[] message = null;
                BigInteger psk = new BigInteger("0");
                String base64EncryptedResponse = "";
                String hexEncryptedResponse = "";
                String challengeString = "";
                switch (choice) {
                    // Encrypt a message
                    case 1:
                        System.out.println("Please enter the message to encrypt: ");
                        response = System.console().readLine().getBytes();
                        encryptedResponse = encryptData(response, cryptoCertificate);
                        System.out.println("Encrypted response: " + encryptedResponse);
                        base64EncryptedResponse = toBase64String(encryptedResponse);
                        System.out.println("Encrypted response (Base64): " + base64EncryptedResponse);
                        System.out.println();
                        break;
                    // Encrypt a message with a psk
                    // Mein result ist hier das Ergebnis aus der Addition in 6)
                    // 1) psk wieder vom result abziehen
                    // 2) result wird encrypted
                    // 3) result wird in hex umgewandelt und ausgegeben
                    case 2:
                        System.out.println("Please enter the result: ");
                        result = new BigInteger(scanner.nextLine());

                        /* Hier code einfügen */
                        psk = new BigInteger("1337");
                        result = result.subtract(psk);
                        String resultFigureAsString = result + "";

                        byte[] encryptedRealRes = encryptData(resultFigureAsString.getBytes(), myOwnCertificate);
                        hexEncryptedResponse = Hex.toHexString(encryptedRealRes);

                        System.out.println("Encrypted response (hex): " + hexEncryptedResponse);
                        System.out.println();
                        break;

                    // Decode a base64-encoded message
                    // 1) decoden aus base64
                    // 2) decrypten mit dem privateKey
                    case 3:
                        System.out.println("Please enter a base64-encrypted challenge: ");
                        
                        /* Hier code einfügen */
                        base64EncryptedResponse = scanner.nextLine();
                        encryptedResponse = Base64.getDecoder().decode(base64EncryptedResponse);
                        decryptedRawChallenge = decryptData(encryptedResponse, privateKey);

                        challengeString = new String(decryptedRawChallenge);

                        System.out.println("Decrypted message: " + challengeString);
                        System.out.println();
                        break;

                    // Decode a hex-encoded message
                    // hex-encoded Challenge wird
                    // 1) decoded aus hex
                    // 2) decrypted mit eigenem key vom selbst erstellten Cert
                    // 3) als String ausgegeben, wo dann wieder die beiden Zahlen enthalten sind
                    case 4:
                        System.out.println("4) Decrypt a hex-encoded message");
                        
                        /* Hier code einfügen */
                        response = scanner.nextLine().getBytes();
                        encryptedResponse = Hex.decode(response);
                        decryptedRawChallenge = decryptData(encryptedResponse,myOwnPrivateKey);

                        System.out.println("Decrypted challenge: " + new String(decryptedRawChallenge));
                        System.out.println();
                        break;
                    // Hashing
                    case 5:
                        int hashingChoice = 0;
                        byte[] mdResult = null;
                        do {
                            System.out.println("Choose a hashing algorithm: ");
                            System.out.println("0) Exit");
                            System.out.println("1) SHA3-224");
                            System.out.println("2) SHA3-256");
                            System.out.println("3) SHA3-384");
                            System.out.println("4) SHA3-512");
                            hashingChoice = Integer.parseInt(System.console().readLine());
                            String hashingAlgorithm = "";
                            boolean abort = false;
                            switch (hashingChoice) {
                                case 0:
                                    abort = true;
                                    break;
                                case 1:
                                    hashingAlgorithm = "SHA3-224";
                                    break;
                                case 2:
                                    hashingAlgorithm = "SHA3-256";
                                    break;
                                case 3:
                                    hashingAlgorithm = "SHA3-384";
                                    break;
                                case 4:
                                    hashingAlgorithm = "SHA3-512";
                                    break;
                                default:
                                    break;
                            }
                            if (!abort) {
                                Path path = Paths.get(System.getProperty("user.dir") + "/hashme.txt");
                                // Alle Daten aus der Datei in ein Byte Array lesen
                                byte[] data = Files.readAllBytes(path);

                                /* Hier code einfügen */
                                // Instanz md von MessageDigest mit entsprechendem SHA3-XXX erstellen
                                MessageDigest md = MessageDigest.getInstance(hashingAlgorithm);
                                // mit md die Daten aus der Datei hashen
                                mdResult = md.digest(data);
                                // Das Hash dann Base64 ausgeben
                                System.out.println(toBase64String(mdResult));
                                hashingChoice = 0;
                            }
                        } while (hashingChoice != 0);
                        System.out.println();
                        break;
                    // Add two comma-separated numbers
                    // Erweitert: gibt das result auch in Base64 und encrypted aus
                    case 6:
                        System.out.println("Please enter two comma-separated numbers: ");
                        String numbersString = scanner.nextLine();
                        String[] numbersArray = numbersString.split(",");
                        BigInteger first = new BigInteger(numbersArray[0]);
                        BigInteger second = new BigInteger(numbersArray[1]);

                        BigInteger res = first.add(second);

                        // res in Base64 TODO
                        String resString = res + "";

                        byte[] encryptedRes = encryptData(resString.getBytes(), cryptoCertificate);
                        String resEncryptedBase64 = Base64.getEncoder().encodeToString(encryptedRes);

                        System.out.println("Sum: " + res);
                        System.out.println("Sum (encrypted-Base64 for semi-safe-ch-resp): " + resEncryptedBase64);
                        System.out.println();
                        break;
                    // Show certificate details of signed hex-encoded message
                    case 7:
                        System.out.println("Please enter hex-encoded message: ");
                        message = Hex.decode(scanner.nextLine());
                        System.out.println();
                        System.out.println(getCertInfoFromMessage(message));
                        System.out.println();
                        break;
                    // Verify signature of hex-encoded message
                    case 8:
                        System.out.println("Please enter hex-encoded message: ");
                        message = Hex.decode(scanner.nextLine());
                        boolean valid = verifySignData(message);
                        System.out.println();
                        System.out.println("Signature is " + (valid ? "valid" : "invalid"));
                        System.out.println();
                        break;
                    default:
                        break;
                }
            }
        } while (choice != 0);
    }

    public static byte[] decryptData(byte[] encryptedData, PrivateKey decryptionKey) throws CMSException {
        byte[] decryptedData = null;

        /* Hier code einfügen */
        if (encryptedData != null && decryptionKey != null) {
            CMSEnvelopedData envelopedData = new CMSEnvelopedData(encryptedData);

            Collection<RecipientInformation> recipients // retrieve all intended recipients of the message
                    = envelopedData.getRecipientInfos().getRecipients();

            KeyTransRecipientInformation recipientInfo
                    = (KeyTransRecipientInformation) recipients.iterator().next();
            JceKeyTransRecipient recipient
                    = new JceKeyTransEnvelopedRecipient(decryptionKey);

            decryptedData = recipientInfo.getContent(recipient);
        }

        return decryptedData;
    }

    public static byte[] encryptData(byte[] data, X509Certificate encryptionCertificate)
            throws CertificateEncodingException, CMSException, IOException {
        byte[] encryptedData = null;

        /* Hier code einfügen */
        if(data != null && encryptionCertificate != null) {
            CMSEnvelopedDataGenerator cmsEnvelopedDataGenerator // created a new CMSEnvelopedDataGenerator object
                    = new CMSEnvelopedDataGenerator();

            JceKeyTransRecipientInfoGenerator jceKey // created a JceKeyTransRecipientInfoGenerator object
                    = new JceKeyTransRecipientInfoGenerator(encryptionCertificate);

            cmsEnvelopedDataGenerator.addRecipientInfoGenerator(jceKey); // added RecipientInfoGenerator into the CMSEnvelopedDataGenerator

            CMSTypedData msg
                    = new CMSProcessableByteArray(data);

            OutputEncryptor encryptor // used to generate a CMSEnvelopedData object that encapsulates the encrypted message
                    = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider("BC").build();

            CMSEnvelopedData cmsEnvelopedData = cmsEnvelopedDataGenerator.generate(msg,encryptor);
            encryptedData = cmsEnvelopedData.getEncoded();
        }
        return encryptedData;
    }

    public static String getCertInfoFromMessage(final byte[] signedData) throws CMSException, IOException {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(signedData);
        ASN1InputStream asn1InputStream = new ASN1InputStream(byteArrayInputStream);
        CMSSignedData cmsSignedData = new CMSSignedData(ContentInfo.getInstance(asn1InputStream.readObject()));
        asn1InputStream.close();
        byteArrayInputStream.close();
        Store<X509CertificateHolder> certs = cmsSignedData.getCertificates();
        SignerInformationStore signers = cmsSignedData.getSignerInfos();
        Collection<SignerInformation> signerInformationCollection = signers.getSigners();
        SignerInformation signer = signerInformationCollection.iterator().next();
        Collection<X509CertificateHolder> certCollection = certs.getMatches(signer.getSID());
        Iterator<X509CertificateHolder> certIt = certCollection.iterator();
        X509CertificateHolder certHolder = certIt.next();

        /* Hier code einfügen */
        String issuer = certHolder.getIssuer().toString();

        return issuer;
    }

    public static boolean verifySignData(final byte[] signedData)
            throws CMSException, IOException, OperatorCreationException, CertificateException {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(signedData);
        ASN1InputStream asn1InputStream = new ASN1InputStream(byteArrayInputStream);
        CMSSignedData cmsSignedData = new CMSSignedData(ContentInfo.getInstance(asn1InputStream.readObject()));
        asn1InputStream.close();
        byteArrayInputStream.close();
        Store<X509CertificateHolder> certs = cmsSignedData.getCertificates();
        SignerInformationStore signers = cmsSignedData.getSignerInfos();
        Collection<SignerInformation> signerInformationCollection = signers.getSigners();
        SignerInformation signer = signerInformationCollection.iterator().next();
        Collection<X509CertificateHolder> certCollection = certs.getMatches(signer.getSID());
        Iterator<X509CertificateHolder> certIt = certCollection.iterator();
        X509CertificateHolder certHolder = certIt.next();
        boolean verifResult = false;

        /* Hier code einfügen */
        try {
            // idk ob ich das wirklich noch brauche
            if (!certHolder.isValidOn(new Date())) {
                return false;
         }
            if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(certHolder))) {
                verifResult = true;
            }
        } catch (Exception e) {
            return false;
        }

        return verifResult;
    }
}
