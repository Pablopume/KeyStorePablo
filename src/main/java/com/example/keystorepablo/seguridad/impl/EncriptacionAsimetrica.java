package com.example.keystorepablo.seguridad.impl;

import com.example.keystorepablo.seguridad.ConstantesSeguridad;
import com.example.keystorepablo.seguridad.EncriptacionAsim;
import io.vavr.control.Either;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
@Component
public class EncriptacionAsimetrica implements EncriptacionAsim {

    @Override
    public Either<ErrorApp, String> encriptar(String texto, PublicKey clavePublica) {
        Either<ErrorApp, String> result;
        try {
            Cipher cifrador = Cipher.getInstance(ConstantesSeguridad.RSA);
            cifrador.init(Cipher.ENCRYPT_MODE, clavePublica);
            byte[] encoded = cifrador.doFinal(texto.getBytes(StandardCharsets.UTF_8));
            result = Either.right(Base64.getUrlEncoder().encodeToString(encoded));
        } catch (Exception e) {
            result = Either.left(new ErrorApp(e.getMessage()));
        }
        return result;
    }

    @Override
    public Either<ErrorApp, String> desencriptar(String textoCifrado, PrivateKey clavePrivada) {
        Either<ErrorApp, String> result;
        byte[] textoCifradoBytes = Base64.getUrlDecoder().decode(textoCifrado);
        try {
            Cipher cifrador = Cipher.getInstance(ConstantesSeguridad.RSA);
            cifrador.init(Cipher.DECRYPT_MODE, clavePrivada);
            byte[] textoDescifradoBytes = cifrador.doFinal(textoCifradoBytes);
            result = Either.right(new String(textoDescifradoBytes, StandardCharsets.UTF_8));
        } catch (Exception e) {
            result = Either.left(new ErrorApp(e.getMessage()));
        }
        return result;
    }
}
