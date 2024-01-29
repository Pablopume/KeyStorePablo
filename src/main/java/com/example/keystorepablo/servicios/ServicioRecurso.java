package com.example.keystorepablo.servicios;

import com.example.keystorepablo.data.RecursoRepsitory;
import com.example.keystorepablo.data.VisualizadorRepository;
import com.example.keystorepablo.domain.modelo.Recurso;
import com.example.keystorepablo.domain.modelo.Visualizador;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;

@Service
public class ServicioRecurso {

    private final PasswordEncoder passwordEncoder;
    private final RecursoRepsitory recursosRepository;
    private final VisualizadorRepository visualizadorRepository;
    @Autowired
    public ServicioRecurso(PasswordEncoder passwordEncoder, RecursoRepsitory recursosRepository, VisualizadorRepository visualizadorRepository) {
        this.passwordEncoder = passwordEncoder;
        this.recursosRepository = recursosRepository;
        this.visualizadorRepository = visualizadorRepository;
    }

    public Recurso crearRecurso(String nombreUsuario, String nombreRecurso, String contraseñaRecurso) {
       Recurso recursos = new Recurso();
        try {
            // Obtener la información del usuario
            KeyPair usuarioKeyPair = obtenerKeyPairUsuario(nombreUsuario);



            // Generar el certificado del recurso
        generarCertificadoRecurso(nombreRecurso, usuarioKeyPair);

            // Firmar la contraseña del recurso con la clave privada del usuario
            byte[] firmaContraseñaRecurso = firmarConClavePrivada(contraseñaRecurso.getBytes(), usuarioKeyPair.getPrivate());

            // Guardar el recurso en la base de datos
            Recurso nuevoRecurso = new Recurso();
            nuevoRecurso.setId(0);
            nuevoRecurso.setNombre(nombreRecurso);
            nuevoRecurso.setPassword(passwordEncoder.encode(contraseñaRecurso));
            nuevoRecurso.setFirma(Base64.getEncoder().encodeToString(firmaContraseñaRecurso));
            nuevoRecurso.setUserfirma(Base64.getEncoder().encodeToString(usuarioKeyPair.getPublic().getEncoded()));
            recursosRepository.save(nuevoRecurso);
            return nuevoRecurso;

        } catch (Exception ex) {
            ex.printStackTrace();
            // Manejar otras excepciones según sea necesario

        }
        return recursos;
    }

    private KeyPair obtenerKeyPairUsuario(String nombreUsuario) {
        try {
            // Cargar el keystore desde el archivo
            char[] keystorePassword = "1234".toCharArray();
            KeyStore ks = KeyStore.getInstance("PKCS12");
            FileInputStream fis = new FileInputStream("keystore.jks");
            ks.load(fis, keystorePassword);
            fis.close();

            // Obtener la clave privada del usuario utilizando su nombre como alias
            char[] userPassword = "1234".toCharArray(); // Contraseña del usuario
            Key userPrivateKey = ks.getKey(nombreUsuario, userPassword);

            // Obtener el certificado del usuario desde el keystore
            X509Certificate userCertificate = (X509Certificate) ks.getCertificate(nombreUsuario);

            // Crear y devolver la KeyPair del usuario
            PublicKey userPublicKey = userCertificate.getPublicKey();
            return new KeyPair(userPublicKey, (PrivateKey) userPrivateKey);

        } catch (Exception ex) {
            ex.printStackTrace();
            // Manejar excepciones según sea necesario
            return null;
        }
    }


    private X509Certificate generarCertificadoRecurso(String nombreRecurso, KeyPair usuarioKeyPair) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // Customize the certificate attributes as needed
        X500Name issuer = new X500Name("CN=" + nombreRecurso);
        X500Name owner = new X500Name("CN=" + nombreRecurso);

        // Crear el generador del certificado
        X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(1),
                new Date(),
                new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000), // Valid for 1 year
                owner,
                SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(usuarioKeyPair.getPublic().getEncoded()))
        );

        // Firmar el certificado con la clave privada del usuario
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(usuarioKeyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(certGen.build(signer));


    }


    private byte[] firmarConClavePrivada(byte[] data, PrivateKey privateKey) throws Exception {
        String algoritmoFirma = "SHA256withRSA";
        Signature firma = Signature.getInstance(algoritmoFirma);
        firma.initSign(privateKey);
        firma.update(data);
        return firma.sign();
    }
}
