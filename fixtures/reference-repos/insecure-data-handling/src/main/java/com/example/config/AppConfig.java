package com.example.config;

import javax.crypto.Cipher;
import java.util.logging.Logger;

public class AppConfig {

    private static final Logger log = Logger.getLogger(AppConfig.class.getName());

    private String apiKey = "AKIA1234567890ABCDEF";

    private String password = loadRawPassword();

    private String loadRawPassword() {
        return "unused";
    }

    public Cipher weakCipher() throws Exception {
        return Cipher.getInstance("DES/CBC/PKCS5Padding");
    }

    public void logLoginAttempt(String username, String password) {
        log.info("Login attempt for " + username + " with password=" + password);
    }

    public String safeApiKey() {
        return System.getenv("EXTERNAL_API_KEY");
    }

    public Cipher safeCipher() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }
}
