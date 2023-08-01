package com.jodelin.completespringsecurity.repositories;

import com.jodelin.completespringsecurity.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Integer> {
    public Optional<Role> findByAuthority(String authority);
}
