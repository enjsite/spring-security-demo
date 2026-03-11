package ru.enjy.spring_security_demo.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.enjy.spring_security_demo.model.RefreshToken;
import ru.enjy.spring_security_demo.model.User;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByToken(String token);

    void deleteByUser(User user);
}
