package ru.enjy.spring_security_demo.data;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import ru.enjy.spring_security_demo.model.Role;
import ru.enjy.spring_security_demo.model.User;
import ru.enjy.spring_security_demo.repository.RoleRepository;
import ru.enjy.spring_security_demo.repository.UserRepository;

@Component
@Profile("dev") //Bash: SPRING_PROFILES_ACTIVE=dev
public class DataInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public DataInitializer(UserRepository userRepository,
                           RoleRepository roleRepository,
                           PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) {

        Role userRole = roleRepository
                .findByName("ROLE_USER")
                .orElseGet(() -> roleRepository.save(
                        new Role(null, "ROLE_USER")));

        Role adminRole = roleRepository
                .findByName("ROLE_ADMIN")
                .orElseGet(() -> roleRepository.save(
                        new Role(null, "ROLE_ADMIN")));

        User user = new User();
        user.setUsername("user");
        user.setPassword(passwordEncoder.encode("1234"));
        user.getRoles().add(userRole);

        User admin = new User();
        admin.setUsername("admin");
        admin.setPassword(passwordEncoder.encode("1234"));
        admin.getRoles().add(adminRole);
        admin.getRoles().add(userRole);

        userRepository.save(user);
        userRepository.save(admin);
    }
}
