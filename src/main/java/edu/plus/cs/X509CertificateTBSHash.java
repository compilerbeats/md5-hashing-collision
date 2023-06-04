package edu.plus.cs;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class X509CertificateTBSHash {

    public static void main(String[] args) {
        String certificateFile1 = "src/main/resources/TargetCollidingCertificate1.cer";
        String certificateFile2 = "src/main/resources/TargetCollidingCertificate2.cer";
        String outputFile1 = "src/main/resources/outputHashCert1.txt";
        String outputFile2 = "src/main/resources/outputHashCert2.txt";

        calculateTBSHash(certificateFile1, outputFile1);
        calculateTBSHash(certificateFile2, outputFile2);
    }

    private static void calculateTBSHash(String certificateFile, String outputFile) {
        try (FileInputStream fis = new FileInputStream(certificateFile)) {
            X509Certificate certificate = loadCertificate(fis);

            byte[] subjectHash = generateTBSHash(certificate, outputFile);
            String subjectHashHex = bytesToHex(subjectHash);
            System.out.println("TBS Hash Cert: " + subjectHashHex);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException | CertificateException e) {
            e.printStackTrace();
        }
    }

    public static X509Certificate loadCertificate(FileInputStream fis) throws CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(fis);
    }

    public static byte[] generateTBSHash(X509Certificate certificate, String outputFile)
            throws CertificateEncodingException, IOException {
        byte[] encodedToBeSignedPart = certificate.getTBSCertificate();
        return MD5Hash.computeMD5(encodedToBeSignedPart, outputFile);
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02X", b));
        }
        return result.toString();
    }
}
