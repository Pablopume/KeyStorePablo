package com.example.keystorepablo.servicios;

import com.example.keystorepablo.Configuration;
import com.example.keystorepablo.data.CredentialsRepository;
import com.example.keystorepablo.domain.modelo.Credentials;
import com.example.keystorepablo.seguridad.impl.ErrorApp;
import io.vavr.control.Either;
import lombok.extern.log4j.Log4j2;
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
import java.util.List;

@Log4j2
@Service
public class ServicioCredentials {
    private final PasswordEncoder passwordEncoder;
    private final CredentialsRepository credentialsRepository;
    private final Configuration configuration;
    @Autowired
    public ServicioCredentials(PasswordEncoder passwordEncoder, CredentialsRepository credentialsRepository, Configuration configuration) {
        this.passwordEncoder = passwordEncoder;
        this.credentialsRepository = credentialsRepository;
        this.configuration = configuration;
    }

    public Either<ErrorApp, Boolean> register(Credentials credentials) {
        Either<ErrorApp, Boolean> result;
        try {
            Security.addProvider(new BouncyCastleProvider());
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ConstantesServicios.RSA);
            keyGen.initialize(2048, new SecureRandom());
            KeyPair userKeyPair = keyGen.generateKeyPair();
            PrivateKey userPrivateKey = userKeyPair.getPrivate();
            PublicKey userPublicKey = userKeyPair.getPublic();
            X509Certificate userCertificate = generateCertificate(credentials.getUsername(), userPublicKey, userKeyPair);
            char[] keystorePassword = configuration.getProperty(ConstantesServicios.CONTRASENYA).toCharArray();
            KeyStore ks = KeyStore.getInstance(ConstantesServicios.PKCS_12);
            ks.load(new FileInputStream(configuration.getProperty(ConstantesServicios.KEYSTORE)), keystorePassword);
            ks.setCertificateEntry(credentials.getUsername(), userCertificate);
            ks.setKeyEntry(credentials.getUsername(), userPrivateKey, keystorePassword, new X509Certificate[]{userCertificate});
            FileOutputStream fos = new FileOutputStream(configuration.getProperty(ConstantesServicios.KEYSTORE));
            ks.store(fos, keystorePassword);
            fos.close();
            credentials.setPassword(passwordEncoder.encode(credentials.getPassword()));
            credentialsRepository.save(credentials);
            result = Either.right(true);
        } catch (Exception ex) {
            log.error(ex.getMessage());
            result = Either.left(new ErrorApp(ConstantesServicios.ERROR_WHILE_REGISTERING_USER));
        }
        return result;
    }

    public Either<ErrorApp, Boolean> doLogin(String username, String password) {
        Either<ErrorApp, Boolean> result;

        Credentials credentials = credentialsRepository.findByUsername(username);
        if (credentials != null) {
            result = Either.right(passwordEncoder.matches(password, credentials.getPassword()));
        } else {
            result = Either.left(new ErrorApp(ConstantesServicios.USER_NOT_FOUND));
        }
        return result;

    }

    private X509Certificate generateCertificate(String username, PublicKey publicKey, KeyPair issuerKeyPair) throws Exception {

        X500Name issuer = new X500Name(ConstantesServicios.CN_ISSUER);
        X500Name owner = new X500Name(ConstantesServicios.CN + username);

        X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(1),
                new Date(),
                new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000),
                owner, SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(publicKey.getEncoded()))
        );

        ContentSigner signer = new JcaContentSignerBuilder(ConstantesServicios.SHA_256_WITH_RSA_ENCRYPTION).build(issuerKeyPair.getPrivate());
        X509CertificateHolder certHolder = certGen.build(signer);
        return new JcaX509CertificateConverter().getCertificate(certHolder);
    }

    public List<Credentials> getAll() {
        return credentialsRepository.findAll();
    }
}
