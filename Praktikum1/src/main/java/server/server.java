package server;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Hex;
import server.EasyShellServer.Command;
import util.DummyFileCreator;
import util.EasyTerminal;

import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;

public class server {
    public static void main(String[] args) throws Exception {
        EasyShellServer telnetServer = new EasyShellServer();
        Security.addProvider(new BouncyCastleProvider());

        char[] keystorePassword = "IchBinNeu0".toCharArray();
        char[] keyPassword = "IchBinNeu0".toCharArray();
        char[] signingKeystorePassword = "1q2w3e4r".toCharArray();
        char[] signingKeyPassword = "1q2w3e4r".toCharArray();
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509", "BC");


        // Einbinden vom eigenen cert
        char[] myOwnKeyStorePassword = "password".toCharArray();
        char[] myOwnKeyPassword = "password".toCharArray();
        X509Certificate myOwnCertificate = (X509Certificate) certFactory
                .generateCertificate(new FileInputStream("Praktikum1/src/main/java/certs/myOwnCert.cer"));
        KeyStore myKeyStore = KeyStore.getInstance("PKCS12");
        myKeyStore.load(new FileInputStream("Praktikum1/src/main/java/certs/myOwnKeyStore.p12"), myOwnKeyStorePassword);
        PrivateKey myOwnPrivateKey = (PrivateKey) myKeyStore.getKey("myOwn", myOwnKeyPassword);



        X509Certificate certificate = (X509Certificate) certFactory
                .generateCertificate(new FileInputStream("Praktikum1/src/main/java/certs/FH.cer"));
        X509Certificate signingCertificate = (X509Certificate) certFactory
                .generateCertificate(new FileInputStream("Praktikum1/src/main/java/certs/signing_cert.cer"));
        X509Certificate signingCertificate1 = (X509Certificate) certFactory
                .generateCertificate(new FileInputStream("Praktikum1/src/main/java/certs/signing_cert1.cer"));

        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(new FileInputStream("Praktikum1/src/main/java/certs/FH.p12"), keystorePassword);
        PrivateKey privateKey = (PrivateKey) keystore.getKey("FH", keyPassword);

        KeyStore signingKeystore = KeyStore.getInstance("PKCS12");
        signingKeystore.load(new FileInputStream("Praktikum1/src/main/java/certs/signing_cert.p12"), signingKeystorePassword);
        PrivateKey signingPrivateKey = (PrivateKey) signingKeystore.getKey("EFFHA", signingKeyPassword);

        KeyStore signingKeystore1 = KeyStore.getInstance("PKCS12");
        signingKeystore1.load(new FileInputStream("Praktikum1/src/main/java/certs/signing_cert1.p12"), signingKeystorePassword);
        PrivateKey signingPrivateKey1 = (PrivateKey) signingKeystore1.getKey("EFFHA", signingKeyPassword);

        telnetServer.registerCommand("echo", new Command() {
            @Override
            public void execute(String name, String argument, EasyTerminal terminal) throws IOException {
                terminal.writeLine(argument);
                terminal.flush();
            }
        });

        telnetServer.registerCommand("helloworld", new Command() {
            @Override
            public void execute(String name, String argument, EasyTerminal terminal) throws IOException {
                terminal.writeLine("Hello World");
                terminal.flush();
            }
        });

        telnetServer.registerCommand("unsafe-ch-resp", new Command() {
            @Override
            public void execute(String name, String argument, EasyTerminal terminal)
                    throws IOException, CMSException, NoSuchAlgorithmException, NoSuchProviderException {
                // Generate random number
                BigInteger[] randomNumbers = generateChallenge();
                BigInteger firstRandomNumber = randomNumbers[0];
                BigInteger secondRandomNumber = randomNumbers[1];
                BigInteger sum = randomNumbers[2];

                // Generate challenge and send to client
                String challenge = firstRandomNumber + "," + secondRandomNumber;

                // Encrypt challenge and send to client
                terminal.writeLine("My challenge: " + challenge);

                // Retrieve response from client and compare to challenge
                terminal.writeLine("Please send me an unencrypted response: ");
                BigInteger response = new BigInteger(terminal.readLine());
                if (response.equals(sum)) {
                    terminal.writeLine("Success");
                } else {
                    terminal.writeLine("Failure");
                }
            }
        });

        telnetServer.registerCommand("semi-safe-ch-resp", new Command() {
            @Override
            public void execute(String name, String argument, EasyTerminal terminal)
                    throws IOException, CMSException, NoSuchAlgorithmException, NoSuchProviderException, CertificateEncodingException {
                // Generate random number
                BigInteger[] randomNumbers = generateChallenge();
                BigInteger firstRandomNumber = randomNumbers[0];
                BigInteger secondRandomNumber = randomNumbers[1];
                BigInteger sum = randomNumbers[2];
                BigInteger result = null;

                // Generate challenge and send to client
                String challenge = firstRandomNumber + "," + secondRandomNumber;

                // Encrypten der Challenge
                byte[] encryptedChallenge = encryptData(challenge.getBytes(), certificate);

                // in Base64 umwandeln
                byte[] encryptedAndBase64 = Base64.getEncoder().encode(encryptedChallenge);

                String var = new String(encryptedAndBase64);
                terminal.writeLine("My challenge: " + var);



                // Retrieve base64-encoded response from client and compare to challenge
                terminal.writeLine("Please send me an encrypted response (in Base64): ");
                
                /* Hier code einfügen */
                byte[] encryptedResponse = Base64.getDecoder().decode(terminal.readLine().getBytes());
                byte[] decryptedRawResponse = decryptData(encryptedResponse, privateKey);
                String res = new String(decryptedRawResponse);

                result = new BigInteger(res);

                if (result.equals(sum)) {
                    terminal.writeLine("Success");
                } else {
                    terminal.writeLine("Failure");
                }
            }
        });

        telnetServer.registerCommand("safe-ch-resp", new Command() {
            @Override
            public void execute(String name, String argument, EasyTerminal terminal)
                    throws IOException, CMSException, CertificateEncodingException, NoSuchAlgorithmException,
                    NoSuchProviderException {
                // Generate random number
                BigInteger[] randomNumbers = generateChallenge();
                BigInteger firstRandomNumber = randomNumbers[0];
                BigInteger secondRandomNumber = randomNumbers[1];
                BigInteger sum = randomNumbers[2];

                // Define psk
                BigInteger psk = new BigInteger("1337");

                // Generate challenge and send to client
                String challenge = firstRandomNumber + "," + (secondRandomNumber.add(psk));

                // Encrypt challenge and send to client
                byte[] encryptedChallenge = encryptData(challenge.getBytes(), myOwnCertificate);

                String hexEncryptedChallenge = Hex.toHexString(encryptedChallenge);
                terminal.writeLine("My hex-encrypted challenge: " + hexEncryptedChallenge);

                // Retrieve hex-encrypted response, decrypt and compare to expected result
                terminal.writeLine("Please send me an encrypted response (in hex): ");
                byte[] encryptedResponse = Hex.decode(terminal.readLine());
                byte[] decryptedRawResponse = decryptData(encryptedResponse, myOwnPrivateKey);
                String decryptedResponse = new String(decryptedRawResponse);
                System.out.println(decryptedResponse);
                BigInteger result = new BigInteger(decryptedResponse);
                if (result.equals(sum)) {
                    terminal.writeLine("Success");
                } else {
                    terminal.writeLine("Failure");
                }
            }
        });

        telnetServer.registerCommand("hashme", new Command() {
            @Override
            public void execute(String name, String argument, EasyTerminal terminal)
                    throws IOException, NoSuchAlgorithmException, NoSuchProviderException {
                // Create file with random content
                DummyFileCreator.createFile();
                // Select random hashing algorithm
                SecureRandom secureRandom = SecureRandom.getInstance("NonceAndIV", "BC");
                String hashingAlgorithm = "";
                MessageDigest md = null;
                byte[] mdResult = null;
                int randomNumber = secureRandom.nextInt(4) + 1;
                switch (randomNumber) {
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
                Path path = Paths.get(System.getProperty("user.dir") + "/hashme.txt");
                byte[] data = Files.readAllBytes(path);
                md = MessageDigest.getInstance(hashingAlgorithm);
                mdResult = md.digest(data);
                terminal.writeLine(
                        "Please send me the " + hashingAlgorithm + " hash value of the file called 'hashme.txt'");
                String hashResult = terminal.readLine();
                if (hashResult.equals(Base64.getEncoder().encodeToString(mdResult))) {
                    terminal.writeLine("Success");
                } else {
                    terminal.writeLine("Failure");
                }
            }
        });

        telnetServer.registerCommand("signData", new Command() {
            @Override
            public void execute(String name, String argument, EasyTerminal terminal) throws Exception {
                terminal.writeLine("I will send you three signed messages. Send me the principal e-mail adress of the valid certificate");
                String message = "I am the real one!   (insert Spiderman meme here ...)";
                byte[] signedRawData1 = signData(message.getBytes(), signingCertificate, signingPrivateKey);
                byte[] signedRawData2 = signData(message.getBytes(), signingCertificate1, signingPrivateKey1);
                byte[] signedRawData3 = signData(message.getBytes(), certificate, privateKey);
                terminal.writeLine("Message 1: " + Hex.toHexString(signedRawData1));
                terminal.writeLine(" ");
                terminal.writeLine(" ");
                terminal.flush();
                terminal.writeLine("Message 2: " + Hex.toHexString(signedRawData2));
                terminal.writeLine(" ");
                terminal.writeLine(" ");
                terminal.flush();
                terminal.writeLine("Message 3: " + Hex.toHexString(signedRawData3));
                terminal.writeLine(" ");
                terminal.writeLine(" ");
                terminal.flush();
                terminal.writeLine("Now, send me the principal e-mail adress of the valid certificate :");
                terminal.flush();
                String email = terminal.readLine();
                String expectedMail = "s.hack@fh-aachen.de";
                if (expectedMail.equals(email)) {
                    terminal.writeLine("Success");
                } else {
                    terminal.writeLine("Failure");
                }
            }
        });

        telnetServer.registerCommand("verify-signData", new Command() {
            @Override
            public void execute(String name, String argument, EasyTerminal terminal) throws Exception {
                terminal.writeLine("I will send you three signed messages. Send me the number of the message containing valid certificate");
                String message = "Y U no believe me?";
                byte[] signedRawData1 = signData(message.getBytes(), signingCertificate, signingPrivateKey1);
                byte[] signedRawData2 = signData(message.getBytes(), signingCertificate1, signingPrivateKey);
                byte[] signedRawData3 = signData(message.getBytes(), certificate, privateKey);
                byte[] signedRawData4 = signData(message.getBytes(), certificate, signingPrivateKey);
                terminal.writeLine("Message 1: " + Hex.toHexString(signedRawData1));
                terminal.writeLine(" ");
                terminal.writeLine(" ");
                terminal.flush();
                terminal.writeLine("Message 2: " + Hex.toHexString(signedRawData2));
                terminal.writeLine(" ");
                terminal.writeLine(" ");
                terminal.flush();
                terminal.writeLine("Message 3: " + Hex.toHexString(signedRawData3));
                terminal.writeLine(" ");
                terminal.writeLine(" ");
                terminal.flush();
                terminal.writeLine("Message 4: " + Hex.toHexString(signedRawData4));
                terminal.writeLine(" ");
                terminal.writeLine(" ");
                terminal.flush();
                // ? terminal.writeLine("Now, send me the principal e-mail adress of the valid certificate :");
                terminal.writeLine("Now send me the number of the message containing a valid certificate :");
                int answer = Integer.valueOf(terminal.readLine());
                int correctMessage = 3;
                if (answer == correctMessage) {
                    terminal.writeLine("Success");
                } else {
                    terminal.writeLine("Failure");
                }
            }
        });

        telnetServer.start(23);
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

    public static byte[] signData(byte[] data, final X509Certificate signingCertificate, final PrivateKey signingKey)
            throws CertificateEncodingException, OperatorCreationException, CMSException, IOException {
        byte[] signedMessage = null;
        List<X509Certificate> certList = new ArrayList<X509Certificate>();
        CMSTypedData cmsData = new CMSProcessableByteArray(data);
        certList.add(signingCertificate);
        Store<X509CertificateHolder> certs = new JcaCertStore(certList);
        CMSSignedDataGenerator cmsGenerator = new CMSSignedDataGenerator();
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(signingKey);
        cmsGenerator.addSignerInfoGenerator(
                new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                        .build(contentSigner, signingCertificate));
        cmsGenerator.addCertificates(certs);
        CMSSignedData cmsSignedData = cmsGenerator.generate(cmsData, true);
        signedMessage = cmsSignedData.getEncoded();
        return signedMessage;
    }

    public static BigInteger[] generateChallenge() throws NoSuchAlgorithmException, NoSuchProviderException {
        SecureRandom secureRandom = SecureRandom.getInstance("NonceAndIV", "BC");
        BigInteger[] result = new BigInteger[3];
        BigInteger firstRandomNumber = BigInteger.valueOf(Math.abs(secureRandom.nextInt()));
        BigInteger secondRandomNumber = BigInteger.valueOf(Math.abs(secureRandom.nextInt()));
        BigInteger sum = firstRandomNumber.add(secondRandomNumber);
        result[0] = firstRandomNumber;
        result[1] = secondRandomNumber;
        result[2] = sum;
        return result;
    }

}