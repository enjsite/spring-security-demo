package ru.enjy.spring_security_demo.controller;

import lombok.Getter;
import lombok.Setter;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.enjy.spring_security_demo.model.RefreshToken;
import ru.enjy.spring_security_demo.model.User;
import ru.enjy.spring_security_demo.repository.RefreshTokenRepository;
import ru.enjy.spring_security_demo.repository.UserRepository;
import ru.enjy.spring_security_demo.security.CustomUserDetailsService;
import ru.enjy.spring_security_demo.security.JwtUtils;
import ru.enjy.spring_security_demo.security.RefreshTokenService;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final CustomUserDetailsService userDetailsService;
    private final JwtUtils jwtUtils;

    private final RefreshTokenService refreshTokenService;

    private final RefreshTokenRepository refreshTokenRepository;

    private final UserRepository userRepository;

    public AuthController(AuthenticationManager authenticationManager,
                          CustomUserDetailsService userDetailsService,
                          JwtUtils jwtUtils,
                          RefreshTokenService refreshTokenService,
                          RefreshTokenRepository refreshTokenRepository,
                          UserRepository userRepository) {
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
        this.jwtUtils = jwtUtils;
        this.refreshTokenService = refreshTokenService;
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository = userRepository;
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody AuthRequest request) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String jwt = jwtUtils.generateToken(userDetails);

        RefreshToken refreshToken =
                refreshTokenService.createRefreshToken(userDetails.getUsername());

        return ResponseEntity.ok(
                Map.of(
                        "accessToken", jwt,
                        "refreshToken", refreshToken.getToken()
                )
        );
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody Map<String, String> request) {

        String requestRefreshToken = request.get("refreshToken");

        RefreshToken refreshToken = refreshTokenRepository
                .findByToken(requestRefreshToken)
                .map(refreshTokenService::verifyExpiration)
                .orElseThrow(() -> new RuntimeException("Token not found"));

        String accessToken = jwtUtils.generateToken(
                new org.springframework.security.core.userdetails.User(
                        refreshToken.getUser().getUsername(),
                        refreshToken.getUser().getPassword(),
                        List.of()
                ));

        return ResponseEntity.ok(
                Map.of(
                        "accessToken", accessToken,
                        "refreshToken", refreshToken.getToken()
                )
        );
    }

    @PostMapping("/logout")
    @Transactional
    public void logout(Authentication authentication) {

        String username = authentication.getName();
        User user = userRepository.findByUsername(username).orElseThrow();
        refreshTokenRepository.deleteByUser(user);
    }

    // DTO для запроса
    @Getter
    @Setter
    public static class AuthRequest {
        private String username;
        private String password;

    }
}
