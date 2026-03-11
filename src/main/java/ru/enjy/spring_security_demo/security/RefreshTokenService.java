package ru.enjy.spring_security_demo.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import ru.enjy.spring_security_demo.model.RefreshToken;
import ru.enjy.spring_security_demo.model.User;
import ru.enjy.spring_security_demo.repository.RefreshTokenRepository;
import ru.enjy.spring_security_demo.repository.UserRepository;

import java.time.Instant;
import java.util.UUID;

@Service
public class RefreshTokenService {

    @Value("${jwt.refresh-expiration}")
    private Long refreshDurationMs;

    private final RefreshTokenRepository repository;
    private final UserRepository userRepository;

    public RefreshTokenService(RefreshTokenRepository repository,
                               UserRepository userRepository) {
        this.repository = repository;
        this.userRepository = userRepository;
    }

    public RefreshToken createRefreshToken(String username) {

        User user = userRepository.findByUsername(username)
                .orElseThrow();

        RefreshToken refreshToken = new RefreshToken();

        refreshToken.setUser(user);
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshDurationMs));
        refreshToken.setToken(UUID.randomUUID().toString());

        return repository.save(refreshToken);
    }

    public RefreshToken verifyExpiration(RefreshToken token) {

        if (token.getExpiryDate().isBefore(Instant.now())) {
            repository.delete(token);
            throw new RuntimeException("Refresh token expired");
        }

        return token;
    }

}
