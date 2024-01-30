package com.example.keystorepablo.servicios;

import com.example.keystorepablo.data.RecursoRepsitory;
import com.example.keystorepablo.data.VisualizadorRepository;
import com.example.keystorepablo.domain.modelo.Recurso;
import com.example.keystorepablo.domain.modelo.Visualizador;
import com.example.keystorepablo.seguridad.Encriptacion;
import com.example.keystorepablo.seguridad.Utils;
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

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

@Service
public class ServicioRecurso {

    private final PasswordEncoder passwordEncoder;
    private final RecursoRepsitory recursosRepository;
    private final VisualizadorRepository visualizadorRepository;
    private final Encriptacion encriptacion;

    @Autowired
    public ServicioRecurso(PasswordEncoder passwordEncoder, RecursoRepsitory recursosRepository, VisualizadorRepository visualizadorRepository, Encriptacion encriptacion) {
        this.passwordEncoder = passwordEncoder;
        this.recursosRepository = recursosRepository;
        this.visualizadorRepository = visualizadorRepository;
        this.encriptacion = encriptacion;
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
            String random = Utils.randomBytes();
            nuevoRecurso.setPassword(encriptacion.encriptar(contraseñaRecurso,random));
            nuevoRecurso.setFirma(Base64.getEncoder().encodeToString(firmaContraseñaRecurso));
            nuevoRecurso.setUserfirma(nombreUsuario);
            recursosRepository.save(nuevoRecurso);

            Visualizador visualizador = new Visualizador();
            String passwordvisualizador = encriptacion.encriptar(random, usuarioKeyPair.getPublic().toString());
            visualizador.setNombre(nombreUsuario);
            visualizador.setPassword(passwordvisualizador);
            visualizador.setRecurso(nuevoRecurso);
            visualizadorRepository.save(visualizador);


            return nuevoRecurso;

        } catch (Exception ex) {
            ex.printStackTrace();
            // Manejar otras excepciones según sea necesario

        }
        return recursos;

    }

    private boolean verificarFirmaContraseñaRecurso(String contraseñaRecurso, byte[] firmaContraseñaRecurso, PublicKey publicKey) throws Exception {
        // Verificar la firma de la contraseña del recurso con la clave pública del usuario
        Signature firma = Signature.getInstance("SHA256withRSA");
        firma.initVerify(publicKey);
        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        firma.update(hash.digest(contraseñaRecurso.getBytes()));
        return firma.verify(firmaContraseñaRecurso);
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

    public byte[] cifrarAsimetricamenteClaveSimetrica(String claveSimetrica, String clavePublica) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // Decodificar la clave pública
        byte[] clavePublicaBytes = Base64.getDecoder().decode(clavePublica);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(clavePublicaBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(x509KeySpec);

        // Cifrar la clave simétrica con la clave pública
        // Aquí debes utilizar el algoritmo de cifrado asimétrico adecuado
        // En este ejemplo, se utiliza RSA para cifrar, pero podría ser otro algoritmo según tus necesidades
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(claveSimetrica.getBytes());
    }

    public static SecretKey generarClaveSimetricaAleatoria() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES"); // Puedes ajustar el algoritmo según tus necesidades
        keyGenerator.init(256); // Puedes ajustar el tamaño de la clave según tus necesidades (128, 192, o 256 bits para AES)
        return keyGenerator.generateKey();
    }

    public boolean crearVisualizador(Recurso recurso, String nombreUusario) throws Exception {

        byte[] claveSimetricaCifrada = cifrarAsimetricamenteClaveSimetrica(generarClaveSimetricaAleatoria().toString(), recurso.getUserfirma());

        // Guardar la clave simétrica cifrada en la tercera tabla (Visualizador)
        Visualizador visualizador = new Visualizador();
        visualizador.setNombre(nombreUusario);  // Ajusta según tus necesidades
        visualizador.setPassword(Base64.getEncoder().encodeToString(claveSimetricaCifrada));
        visualizador.setRecurso(recurso);
        visualizadorRepository.save(visualizador);
        return true;
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
        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        firma.update(hash.digest(data));
        return firma.sign();
    }
}
