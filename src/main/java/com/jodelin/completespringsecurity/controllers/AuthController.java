package com.jodelin.completespringsecurity.controllers;

import com.jodelin.completespringsecurity.dto.RegisterUserDto;
import com.jodelin.completespringsecurity.service.MyServiceUser;
import com.jodelin.completespringsecurity.service.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("auth")
@RequiredArgsConstructor
public class AuthController {
    private final MyServiceUser myServiceUser;
    private final AuthenticationManager manager;
    private final TokenService tokenService;

    @PostMapping("/login")
    public Map<String, String> regsiter(@RequestBody RegisterUserDto registerUserDto) {
        //  return myServiceUser.registerUser(registerUserDto.getUsername(),registerUserDto.getPassword());
        Authentication authentication = manager.authenticate(new UsernamePasswordAuthenticationToken(registerUserDto.getUsername(), registerUserDto.getPassword()));
        Map<String, String> map = new HashMap<>();
        map.put("token", tokenService.generateToken(authentication));
        return map;
    }
}
