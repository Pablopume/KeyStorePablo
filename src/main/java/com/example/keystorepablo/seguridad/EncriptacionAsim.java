package com.example.keystorepablo.seguridad;

import com.example.keystorepablo.seguridad.impl.ErrorApp;
import io.vavr.control.Either;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface EncriptacionAsim {
    Either<ErrorApp, String> encriptar(String texto, PublicKey clavePublica);
    Either<ErrorApp, String> desencriptar(String texto, PrivateKey clavePrivada);
}
