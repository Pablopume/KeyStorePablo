package com.example.keystorepablo.servicios;

import com.example.keystorepablo.data.VisualizadorRepository;
import com.example.keystorepablo.domain.modelo.Recurso;
import com.example.keystorepablo.domain.modelo.Visualizador;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Service
public class ServiceVisualizador {
    private final VisualizadorRepository visualizadoresRepository;
    @Autowired
    public ServiceVisualizador(VisualizadorRepository visualizadoresRepository) {
        this.visualizadoresRepository = visualizadoresRepository;
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
        visualizadoresRepository.save(visualizador);
        return true;
    }
}
