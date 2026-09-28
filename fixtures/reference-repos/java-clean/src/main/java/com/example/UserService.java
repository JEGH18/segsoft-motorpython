package com.example;

import java.sql.PreparedStatement;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import org.springframework.web.bind.annotation.PostMapping;
import io.github.bucket4j.Bucket;
import org.mindrot.jbcrypt.BCrypt;
import com.auth0.jwt.JWT;

/**
 * Fixture "sano" para PDGSEGSOFT-23: cada patrón de aqui es el equivalente
 * seguro/corregido del patron vulnerable que las 23 reglas activas buscan.
 * No debe disparar NINGUN hallazgo -- sirve para medir precision (falsos
 * positivos) del motor.
 */
public class UserService {

    private final Bucket loginRateLimiter = Bucket.builder().build();

    public void findOrder(String orderId, PreparedStatement ps) throws Exception {
        // Consulta parametrizada, sin concatenacion
        ps.setString(1, orderId);
        ps.executeQuery();
    }

    public String buildOrderSummaryQuery() {
        return "SELECT id, total, status FROM orders WHERE customer_id = ?";
    }

    public boolean isPasswordStrong(String password) {
        return password.length() >= 12;
    }

    @PostMapping("/login") // protegido con Bucket4j RateLimiter, ver loginRateLimiter arriba
    public void login(String username, String rawPassword) {
        if (!loginRateLimiter.tryConsume(1)) {
            throw new RuntimeException("Too many attempts");
        }
    }

    public String issueToken(String subject) {
        Instant expiresAt = Instant.now().plus(1, ChronoUnit.HOURS);
        return JWT.create().withSubject(subject).withExpiresAt(expiresAt).sign(null);
    }

    public String hashPassword(String rawPassword) {
        return BCrypt.hashpw(rawPassword, BCrypt.gensalt());
    }

    public String apiKeyFromEnvironment() {
        return System.getenv("EXTERNAL_API_KEY");
    }
}
