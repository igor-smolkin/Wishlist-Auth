package org.ataraxii.authwishlist.security.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.ataraxii.authwishlist.security.dto.login.LoginRequestDto;
import org.ataraxii.authwishlist.security.dto.login.LoginResponseDto;
import org.ataraxii.authwishlist.security.dto.register.RegisterRequestDto;
import org.ataraxii.authwishlist.security.dto.register.RegisterResponseDto;
import org.ataraxii.authwishlist.security.dto.token.RefreshRequestDto;
import org.ataraxii.authwishlist.security.dto.token.RefreshResponseDto;
import org.ataraxii.authwishlist.security.service.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<LoginResponseDto> login(@RequestBody LoginRequestDto request) {
            LoginResponseDto response = authService.login(request);
            return ResponseEntity.ok(response);
    }

    @PostMapping("/register")
    public ResponseEntity<RegisterResponseDto> register(@RequestBody RegisterRequestDto request) {
        RegisterResponseDto response = authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/refresh")
    public ResponseEntity<RefreshResponseDto> refresh(@RequestBody RefreshRequestDto request) {
        RefreshResponseDto response = authService.refresh(request);
        return ResponseEntity.ok(response);
    }
}
