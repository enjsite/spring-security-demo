package ru.enjy.spring_security_demo.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.enjy.spring_security_demo.model.Role;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(String name);
}
