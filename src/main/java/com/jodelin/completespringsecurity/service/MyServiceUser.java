package com.jodelin.completespringsecurity.service;

import com.jodelin.completespringsecurity.models.Role;
import com.jodelin.completespringsecurity.models.User;
import com.jodelin.completespringsecurity.repositories.RoleRepository;
import com.jodelin.completespringsecurity.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class MyServiceUser {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public User registerUser(String username, String password) {
        String encodedPassword = passwordEncoder.encode(password);
        Role userRole = roleRepository.findByAuthority("ADMIN").get();
        Set<Role> roles = new HashSet<>();
        roles.add(userRole);

        return userRepository.save(User.builder()
                .userId(2)
                .username(username)
                .password(encodedPassword)
                .authorities(roles)
                .build()
        );
    }
}
