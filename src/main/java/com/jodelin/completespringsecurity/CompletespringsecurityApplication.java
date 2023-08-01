package com.jodelin.completespringsecurity;

import com.jodelin.completespringsecurity.models.Role;
import com.jodelin.completespringsecurity.models.User;
import com.jodelin.completespringsecurity.repositories.RoleRepository;
import com.jodelin.completespringsecurity.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashSet;
import java.util.Set;

@SpringBootApplication
@RequiredArgsConstructor
public class CompletespringsecurityApplication implements CommandLineRunner {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public static void main(String[] args) {
        SpringApplication.run(CompletespringsecurityApplication.class, args);
    }

    @Override
    public void run(String... args) throws Exception {
        extracted();
    }

    private void extracted() {
        Role role = Role.builder()
                .roleId(1)
                .authority("ADMIN")
                .build();
        Set<Role> roles = new HashSet<>();
        roles.add(role);
        User user = User.builder()
                .userId(1)
                .username("jodelin93")
                .password(passwordEncoder.encode("jodelin"))
                .authorities(roles)
                .build();
        user.setAuthorities(roles);
        userRepository.save(user);
    }
}
