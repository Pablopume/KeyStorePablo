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


}
