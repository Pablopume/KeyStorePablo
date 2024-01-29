package com.example.keystorepablo.servicios;

import com.example.keystorepablo.data.CredentialsRepository;
import com.example.keystorepablo.domain.modelo.Credentials;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;

@Service
public class ServicioCredentials {
    private final PasswordEncoder passwordEncoder;
    private final CredentialsRepository credentialsRepository;

    @Autowired
    public ServicioCredentials(PasswordEncoder passwordEncoder, CredentialsRepository credentialsRepository) {
        this.passwordEncoder = passwordEncoder;
        this.credentialsRepository = credentialsRepository;
    }

    public boolean register(Credentials credentials) {
        boolean result = false;

        try {
            Security.addProvider(new BouncyCastleProvider());

            // Step 1: Generate a key pair
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048, new SecureRandom());
            KeyPair userKeyPair = keyGen.generateKeyPair();
            PrivateKey userPrivateKey = userKeyPair.getPrivate();
            PublicKey userPublicKey = userKeyPair.getPublic();

            // Step 2: Create an X.509 certificate for the user
            X509Certificate userCertificate = generateCertificate(credentials.getUsername(), userPublicKey, userKeyPair);

            // Step 3: Store the user's public key and certificate in the KeyStore
            char[] keystorePassword = "1234".toCharArray();
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(new FileInputStream("keystore.jks"), keystorePassword);

            // Store the public key and certificate with a unique alias (e.g., username)
            ks.setCertificateEntry(credentials.getUsername(), userCertificate);
            ks.setKeyEntry(credentials.getUsername(), userPrivateKey, keystorePassword, new X509Certificate[]{userCertificate});


            // Save the updated KeyStore to the file
            FileOutputStream fos = new FileOutputStream("keystore.jks");
            ks.store(fos, keystorePassword);
            fos.close();

            // Save the credentials in the database
            credentials.setPassword(passwordEncoder.encode(credentials.getPassword()));
            credentialsRepository.save(credentials);
            result = true;
        } catch (Exception ex) {
            ex.printStackTrace();
            // Handle exceptions appropriately
        }
        return result;
    }

    public boolean doLogin(String username, String password) {
        boolean result = false;
        Credentials credentials = credentialsRepository.findByUsername(username);
        if (credentials != null) {
            result = passwordEncoder.matches(password, credentials.getPassword());
        }
        return result;

    }
    private X509Certificate generateCertificate(String username, PublicKey publicKey, KeyPair issuerKeyPair) throws Exception {
        // Customize the certificate attributes as needed
        X500Name issuer = new X500Name("CN=Issuer");
        X500Name owner = new X500Name("CN=" + username);

        X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(1),
                new Date(),
                new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000), // Valid for 1 year
                owner, SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(publicKey.getEncoded()))
        );

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(issuerKeyPair.getPrivate());
        X509CertificateHolder certHolder = certGen.build(signer);
        return new JcaX509CertificateConverter().getCertificate(certHolder);
    }
}
