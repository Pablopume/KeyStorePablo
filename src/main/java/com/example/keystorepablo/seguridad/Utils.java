package com.example.keystorepablo.seguridad;

import java.security.SecureRandom;
import java.util.Base64;

/**
 *
 * @author oscar
 */
public class Utils {


    public static String randomBytes()
    {
        SecureRandom sr = new SecureRandom();
        byte[] bits = new byte[32];
        sr.nextBytes(bits);
        return Base64.getUrlEncoder().encodeToString(bits);
    }

    private Utils() {
    }
}