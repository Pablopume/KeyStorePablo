package com.example.keystorepablo;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

public class Main {

    public static void main(String[] args) throws Exception {
        generateAndSaveAutoSignedCertificate();
    }

    public static void generateAndSaveAutoSignedCertificate() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        X509Certificate cert = createSelfSignedCertificate("server", publicKey, privateKey);
        saveCertificateAndPrivateKeyToKeystore(cert, privateKey, "server", "1234");
    }

    private static X509Certificate createSelfSignedCertificate(String username, PublicKey publicKey, PrivateKey privateKey) throws Exception {
        X500Name owner = new X500Name("CN=" + username);
        X500Name issuer = owner; // Self-signed certificate has the same issuer and owner
        // Creating a self-signed certificate
        X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(1),
                new Date(),
                new Date(System.currentTimeMillis() + 1000000),
                owner, SubjectPublicKeyInfo.getInstance(
                ASN1Sequence.getInstance(publicKey.getEncoded()))
        );
        // Signing the certificate with its own private key
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(privateKey);
        X509CertificateHolder certHolder = certGen.build(signer);
        return new JcaX509CertificateConverter().getCertificate(certHolder);
    }

    private static void saveCertificateAndPrivateKeyToKeystore(X509Certificate cert, PrivateKey privateKey, String username, String userPassword) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setCertificateEntry(username, cert);
        ks.setKeyEntry(username, privateKey, userPassword.toCharArray(), new Certificate[]{cert});
        FileOutputStream fos = new FileOutputStream("keystore.jks");
        ks.store(fos, "1234".toCharArray());
        fos.close();
    }
}