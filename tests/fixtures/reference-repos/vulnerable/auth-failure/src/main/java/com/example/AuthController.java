package com.example;

import com.auth0.jwt.JWT;
import org.springframework.web.bind.annotation.PostMapping;

public class AuthController {

    public String issueToken(String subject) {
        return JWT.create().withSubject(subject).sign(null);
    }

    @PostMapping("/login")
    public void login(String username, String password) {
        if (password.matches("\\d{6}")) {
            throw new IllegalArgumentException("weak password");
        }
    }
}
