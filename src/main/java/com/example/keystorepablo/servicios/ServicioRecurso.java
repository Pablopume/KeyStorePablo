package com.example.keystorepablo.servicios;

import com.example.keystorepablo.Configuration;
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
    private final RecursoRepsitory recursosRepository;
    private final VisualizadorRepository visualizadorRepository;
    private final Encriptacion encriptacion;
    private final Configuration configuration;

    @Autowired
    public ServicioRecurso(EncriptacionAsim encriptacionAsim, RecursoRepsitory recursosRepository, VisualizadorRepository visualizadorRepository, Encriptacion encriptacion, Configuration configuration) {
        this.encriptacionAsim = encriptacionAsim;

        this.recursosRepository = recursosRepository;
        this.visualizadorRepository = visualizadorRepository;
        this.encriptacion = encriptacion;
        this.configuration = configuration;
    }


    public Either<ErrorApp, Recurso> crearRecurso(String nombreUsuario, String nombreRecurso, String contrasenyaRecurso) {

        Either<ErrorApp, Recurso> result;
        try {
            KeyPair usuarioKeyPair = obtenerKeyPairUsuario(nombreUsuario);
            generarCertificadoRecurso(nombreRecurso, usuarioKeyPair);
            String firmaContrasenyaRecurso = firmarConClavePrivada(contrasenyaRecurso.getBytes(), usuarioKeyPair.getPrivate());
            Recurso nuevoRecurso = new Recurso();
            nuevoRecurso.setId(0);
            nuevoRecurso.setNombre(nombreRecurso);
            String random = Utils.randomBytes();
            nuevoRecurso.setPassword(encriptacion.encriptar(contrasenyaRecurso, random));
            nuevoRecurso.setFirma(firmaContrasenyaRecurso);
            nuevoRecurso.setUserfirma(nombreUsuario);
            recursosRepository.save(nuevoRecurso);
            Visualizador visualizador = new Visualizador();
            String passwordvisualizador = encriptacionAsim.encriptar(random, usuarioKeyPair.getPublic()).get();
            visualizador.setNombre(nombreUsuario);
            visualizador.setPassword(passwordvisualizador);
            visualizador.setRecurso(nuevoRecurso);
            visualizadorRepository.save(visualizador);


            result = Either.right(nuevoRecurso);

        } catch (Exception ex) {
            result = Either.left(new ErrorApp(ConstantesServicios.ERROR_AL_CREAR_EL_RECURSO));
        }
        return result;

    }

    private String firmarConClavePrivada(byte[] data, PrivateKey privateKey) throws Exception {
        String algoritmoFirma = ConstantesServicios.SHA_256_WITH_RSA;
        Signature firma = Signature.getInstance(algoritmoFirma);
        firma.initSign(privateKey);
        MessageDigest hash = MessageDigest.getInstance(ConstantesServicios.SHA_256);
        firma.update(hash.digest(data));

        return Base64.getEncoder().encodeToString(firma.sign());
    }

    public Either<ErrorApp, Boolean> verificarFirmaRecurso(Recurso recurso, String nombreUsuario) {
        Either<ErrorApp, Boolean> result = null;
        try {
            KeyPair usuarioKeyPair = obtenerKeyPairUsuario(nombreUsuario);
            if (usuarioKeyPair != null) {


                String firmaAlmacenada = recurso.getFirma();
                String contrasenyaRecurso = recurso.getPassword();
                Visualizador visualizador = visualizadorRepository.findVisualizadorByRecursoAndNombre(recurso, nombreUsuario);
                String random = encriptacionAsim.desencriptar(visualizador.getPassword(), usuarioKeyPair.getPrivate()).get();
                String decryptedPassword = encriptacion.desencriptar(contrasenyaRecurso, random);
                String firmaGenerada = firmarConClavePrivada(decryptedPassword.getBytes(), usuarioKeyPair.getPrivate());
                result = Either.right(firmaAlmacenada.equals(firmaGenerada));
            }
        } catch (Exception ex) {
            result = Either.left(new ErrorApp(ConstantesServicios.ERROR_AL_VERIFICAR_LA_FIRMA));
        }
        return result;
    }

    public Either<ErrorApp, Boolean> changePassword(String username, String password, Recurso recurso) throws Exception {
        Either<ErrorApp, Boolean> result = null;
        KeyPair usuarioKeyPair = obtenerKeyPairUsuario(username);
        Visualizador as = visualizadorRepository.findByNombreAndRecurso(username, recurso);
        if (usuarioKeyPair != null) {
            Either<ErrorApp, String> random = encriptacionAsim.desencriptar(as.getPassword(), usuarioKeyPair.getPrivate());
            String firma = firmarConClavePrivada(password.getBytes(), usuarioKeyPair.getPrivate());

            if (random.isRight()) {
                String passwordEncriptada = encriptacion.encriptar(password, random.get());
                recurso.setPassword(passwordEncriptada);
                recurso.setFirma(firma);
                recurso.setUserfirma(username);
                recursosRepository.save(recurso);
                result = Either.right(true);
            } else {
                result = Either.left(new ErrorApp(ConstantesServicios.ERROR_AL_CAMBIAR_LA_CONTRASENYA));
            }
        }
        return result;
    }

    public List<Recurso> getAllRecursos(String nombreUsuario) {
        return visualizadorRepository.findByNombre(nombreUsuario).stream().map(Visualizador::getRecurso).toList();
    }

    public Either<ErrorApp, Visualizador> compartirRecurso(String nombreOwner, String nombreVisualizador, Recurso recurso) {
        Either<ErrorApp, Visualizador> result = Either.left(new ErrorApp(ConstantesServicios.ERROR_AL_COMPARTIR_EL_RECURSO));
        KeyPair usuarioKeyPair = obtenerKeyPairUsuario(nombreOwner);
        KeyPair visualizadorKeyPair = obtenerKeyPairUsuario(nombreVisualizador);

        Visualizador visualizador = visualizadorRepository.findByNombreAndRecurso(nombreOwner, recurso);
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

            char[] keystorePassword = configuration.getProperty(ConstantesServicios.CONTRASENYA).toCharArray();
            KeyStore ks = KeyStore.getInstance(ConstantesServicios.PKCS_12);
            FileInputStream fis = new FileInputStream(configuration.getProperty(ConstantesServicios.KEYSTORE));
            ks.load(fis, keystorePassword);
            fis.close();

            char[] userPassword = configuration.getProperty(ConstantesServicios.CONTRASENYA).toCharArray(); // Contraseña del usuario
            Key userPrivateKey = ks.getKey(nombreUsuario, userPassword);
            X509Certificate userCertificate = (X509Certificate) ks.getCertificate(nombreUsuario);
            PublicKey userPublicKey = userCertificate.getPublicKey();
            return new KeyPair(userPublicKey, (PrivateKey) userPrivateKey);

        } catch (Exception ex) {
            log.error(ex.getMessage());
            // Manejar excepciones según sea necesario
            return null;
        }
    }


    private X509Certificate generarCertificadoRecurso(String nombreRecurso, KeyPair usuarioKeyPair) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // Customize the certificate attributes as needed
        X500Name issuer = new X500Name("CN=" + nombreRecurso);
        X500Name owner = new X500Name("CN=" + nombreRecurso);

        X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(1),
                new Date(),
                new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000),
                owner,
                SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(usuarioKeyPair.getPublic().getEncoded()))
        );

        // Firmar el certificado con la clave privada del usuario
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(usuarioKeyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(certGen.build(signer));


    }


}
