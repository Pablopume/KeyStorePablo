package com.example.keystorepablo.servicios;

import com.example.keystorepablo.data.RecursoRepsitory;
import com.example.keystorepablo.data.VisualizadorRepository;
import com.example.keystorepablo.domain.modelo.Recurso;
import com.example.keystorepablo.domain.modelo.Visualizador;
import com.example.keystorepablo.seguridad.Encriptacion;
import com.example.keystorepablo.seguridad.EncriptacionAsim;
import com.example.keystorepablo.seguridad.Utils;
import com.example.keystorepablo.seguridad.impl.ErrorApp;
import io.vavr.control.Either;
import lombok.extern.log4j.Log4j2;
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
import java.util.List;

@Log4j2
@Service
public class ServicioRecurso {
    private final EncriptacionAsim encriptacionAsim;
    private final PasswordEncoder passwordEncoder;
    private final RecursoRepsitory recursosRepository;
    private final VisualizadorRepository visualizadorRepository;
    private final Encriptacion encriptacion;

    @Autowired
    public ServicioRecurso(EncriptacionAsim encriptacionAsim, PasswordEncoder passwordEncoder, RecursoRepsitory recursosRepository, VisualizadorRepository visualizadorRepository, Encriptacion encriptacion) {
        this.encriptacionAsim = encriptacionAsim;
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
            String firmaContraseñaRecurso = firmarConClavePrivada(contraseñaRecurso.getBytes(), usuarioKeyPair.getPrivate());

            // Guardar el recurso en la base de datos
            Recurso nuevoRecurso = new Recurso();
            nuevoRecurso.setId(0);
            nuevoRecurso.setNombre(nombreRecurso);
            String random = Utils.randomBytes();
            nuevoRecurso.setPassword(encriptacion.encriptar(contraseñaRecurso, random));
            nuevoRecurso.setFirma(firmaContraseñaRecurso);
            nuevoRecurso.setUserfirma(nombreUsuario);
            recursosRepository.save(nuevoRecurso);

            Visualizador visualizador = new Visualizador();
            String passwordvisualizador = encriptacionAsim.encriptar(random, usuarioKeyPair.getPublic()).get();
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

    private String firmarConClavePrivada(byte[] data, PrivateKey privateKey) throws Exception {
        String algoritmoFirma = "SHA256withRSA";
        Signature firma = Signature.getInstance(algoritmoFirma);
        firma.initSign(privateKey);
        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        firma.update(hash.digest(data));
        return Base64.getEncoder().encodeToString(firma.sign());
    }

    public boolean verificarFirmaRecurso(Recurso recurso, String nombreUsuario) {
        try {
            KeyPair usuarioKeyPair = obtenerKeyPairUsuario(nombreUsuario);
            String firmaAlmacenada = recurso.getFirma();
            String contraseñaRecurso = recurso.getPassword();
            Visualizador visualizador = visualizadorRepository.findVisualizadorByRecursoAndNombre(recurso, nombreUsuario);
            String random = encriptacionAsim.desencriptar(visualizador.getPassword(), usuarioKeyPair.getPrivate()).get();
            String decryptedPassword = encriptacion.desencriptar(contraseñaRecurso, random);
            String firmaGenerada = firmarConClavePrivada(decryptedPassword.getBytes(), usuarioKeyPair.getPrivate());
            return firmaAlmacenada.equals(firmaGenerada);
        } catch (Exception ex) {
            log.error("Error al verificar la firma del recurso", ex);
            // Manejar otras excepciones según sea necesario
        }
        return false;
    }

    public boolean changePassword(String username, String password, Recurso recurso) throws Exception {
        KeyPair usuarioKeyPair = obtenerKeyPairUsuario(username);
        Visualizador as = visualizadorRepository.findByNombreAndRecurso(username, recurso);

        Either<ErrorApp, String> random = encriptacionAsim.desencriptar(as.getPassword(), usuarioKeyPair.getPrivate());
        String firma = firmarConClavePrivada(password.getBytes(), usuarioKeyPair.getPrivate());

        if (random.isRight()) {
            String passwordEncriptada = encriptacion.encriptar(password, random.get());
            recurso.setPassword(passwordEncriptada);
            recurso.setFirma(firma);
            recurso.setUserfirma(username);
            recursosRepository.save(recurso);
            return true;
        } else {
            return false;
        }
    }

    public List<Recurso> getAllRecursos(String nombreUsuario) {
        return visualizadorRepository.findByNombre(nombreUsuario).stream().map(Visualizador::getRecurso).toList();
    }

    public Either<ErrorApp, Visualizador> compartirRecurso(String nombreDueño, String nombreVisualizador, Recurso recurso) {
        Either<ErrorApp, Visualizador> result = Either.left(new ErrorApp("Error al compartir el recurso"));
        KeyPair usuarioKeyPair = obtenerKeyPairUsuario(nombreDueño);
        KeyPair visualizadorKeyPair = obtenerKeyPairUsuario(nombreVisualizador);

        Visualizador visualizador = visualizadorRepository.findByNombreAndRecurso(nombreDueño, recurso);
        if (usuarioKeyPair != null && visualizadorKeyPair != null) {
            String randomizador = encriptacionAsim.desencriptar(visualizador.getPassword(), usuarioKeyPair.getPrivate()).get();
            String passwordEncripted = encriptacionAsim.encriptar(randomizador, visualizadorKeyPair.getPublic()).get();
            Visualizador visualizador1 = new Visualizador();
            visualizador1.setNombre(nombreVisualizador);
            visualizador1.setPassword(passwordEncripted);
            visualizador1.setRecurso(recurso);
            visualizadorRepository.save(visualizador1);
            result = Either.right(visualizador1);
        }
        return result;
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


}
