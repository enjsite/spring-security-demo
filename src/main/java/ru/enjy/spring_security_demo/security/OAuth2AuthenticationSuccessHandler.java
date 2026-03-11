package ru.enjy.spring_security_demo.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import ru.enjy.spring_security_demo.model.RefreshToken;
import ru.enjy.spring_security_demo.model.Role;
import ru.enjy.spring_security_demo.model.User;
import ru.enjy.spring_security_demo.repository.RoleRepository;
import ru.enjy.spring_security_demo.repository.UserRepository;

import java.io.IOException;
import java.util.Map;
import java.util.Set;

@Component
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtUtils jwtUtils;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    private final CustomUserDetailsService customUserDetailsService;

    private final RefreshTokenService refreshTokenService;

    public OAuth2AuthenticationSuccessHandler(JwtUtils jwtUtils, UserRepository userRepository,
                                              RoleRepository roleRepository,
                                              PasswordEncoder passwordEncoder,
                                              CustomUserDetailsService customUserDetailsService,
                                              RefreshTokenService refreshTokenService) {
        this.jwtUtils = jwtUtils;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.customUserDetailsService = customUserDetailsService;
        this.refreshTokenService = refreshTokenService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        String email = oAuth2User.getAttribute("email");

        // Создаем или обновляем пользователя в БД
        User user = userRepository.findByUsername(email)
                .orElseGet(() -> {
                    User newUser = new User();
                    newUser.setUsername(email);
                    // Заглушка для пароля, чтобы JPA не ругалось
                    newUser.setPassword(passwordEncoder.encode("oauth2user"));

                    // Получаем существующую роль из БД
                    Role userRole = roleRepository.findByName("ROLE_USER")
                            .orElseThrow(() -> new RuntimeException("Role ROLE_USER not found"));

                    newUser.setRoles(Set.of(userRole));
                    return userRepository.save(newUser);
                });

        // Генерация JWT
        UserDetails userDetails = customUserDetailsService.loadUserByUsername(user.getUsername());
        String token = jwtUtils.generateToken(userDetails);

        RefreshToken refreshToken =
                refreshTokenService.createRefreshToken(userDetails.getUsername());

        // Возвращаем токен в теле ответа
        response.setContentType("application/json");
        response.getWriter().write("{\"accessToken\":\"" + token + "\", \"refreshToken\":\"" + refreshToken.getToken() + "\"}");
    }
}
