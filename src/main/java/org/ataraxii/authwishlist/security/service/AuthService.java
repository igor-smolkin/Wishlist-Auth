package org.ataraxii.authwishlist.security.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.ataraxii.authwishlist.database.entity.RefreshToken;
import org.ataraxii.authwishlist.database.entity.Role;
import org.ataraxii.authwishlist.database.entity.RoleType;
import org.ataraxii.authwishlist.database.entity.User;
import org.ataraxii.authwishlist.database.repository.RefreshTokenRepository;
import org.ataraxii.authwishlist.database.repository.RoleRepository;
import org.ataraxii.authwishlist.database.repository.UserRepository;
import org.ataraxii.authwishlist.exception.ConflictException;
import org.ataraxii.authwishlist.exception.InvalidTokenException;
import org.ataraxii.authwishlist.exception.NotFoundException;
import org.ataraxii.authwishlist.security.dto.login.LoginRequestDto;
import org.ataraxii.authwishlist.security.dto.login.LoginResponseDto;
import org.ataraxii.authwishlist.security.dto.register.RegisterRequestDto;
import org.ataraxii.authwishlist.security.dto.register.RegisterResponseDto;
import org.ataraxii.authwishlist.security.dto.token.RefreshRequestDto;
import org.ataraxii.authwishlist.security.dto.token.RefreshResponseDto;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RoleRepository roleRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenRepository refreshTokenRepository;

    public RegisterResponseDto register(RegisterRequestDto request) {
        log.info("Попытка регистрации: username={}", request.getUsername());
        if (userRepository.existsByUsername(request.getUsername())) {
            log.warn("Ошибка регистрации: пользователь с именем '{}' уже существует", request.getUsername());
            throw new ConflictException("Пользователь с таким именем уже существует");
        }

        Role userRole = roleRepository.findByName(RoleType.USER)
                .orElseThrow(() -> new NotFoundException("Роль USER не найдена"));

        String hashedPassword = passwordEncoder.encode(request.getPassword());

        User user = User.builder()
                .username(request.getUsername())
                .password(hashedPassword)
                .isEnabled(true)
                .createdAt(Instant.now())
                .roles(Set.of(userRole))
                .build();

        userRepository.save(user);

        log.info("Пользователь '{}' успешно зарегистрирован", user.getUsername());

        return RegisterResponseDto.builder()
                .username(user.getUsername())
                .message("Пользователь успешно зарегистрирован")
                .build();
    }

    public LoginResponseDto login(LoginRequestDto request) {
        try {
            log.info("Попытка входа: username='{}'", request.getUsername());
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getUsername(),
                            request.getPassword()
                    )
            );

            User user = userRepository.findByUsername(authentication.getName())
                    .orElseThrow(() -> new NotFoundException("Пользователь не найден"));

            List<RoleType> roles = user.getRoles().stream()
                    .map(Role::getName)
                    .toList();

            String accessToken = jwtService.generateAccessToken(user.getUsername(), user.getId(), roles);
            String refreshToken = jwtService.generateRefreshToken(user.getUsername());

            Date expiryDate = jwtService.getRefreshTokenExpiryDate();

            refreshTokenRepository.save(
                    RefreshToken.builder()
                            .user(user)
                            .token(refreshToken)
                            .expiryDate(expiryDate.toInstant())
                            .build()
            );

            log.info("Успешный вход: username='{}'", request.getUsername());
            return new LoginResponseDto(accessToken, refreshToken);
        } catch (BadCredentialsException e) {
            log.warn("Ошибка входа: username='{}' неверный логин или пароль", request.getUsername());
            throw e;
        } catch (DisabledException e) {
            log.warn("Ошибка входа: username='{}' пользователь деактивирован", request.getUsername());
            throw e;
        }
    }

    public RefreshResponseDto refresh(RefreshRequestDto request) {
        if (!jwtService.validateToken(request.getRefreshToken())) {
            throw new InvalidTokenException("Refresh токен недействителен");
        }

        RefreshToken storedToken = refreshTokenRepository.findByToken(request.getRefreshToken())
                .orElseThrow(() -> new InvalidTokenException("Refresh токен не найден"));

        String username = jwtService.extractUsername(request.getRefreshToken());

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new NotFoundException("Пользователь не найден"));

        List<RoleType> roles = user.getRoles().stream()
                .map(Role::getName)
                .toList();

        String accessToken = jwtService.generateAccessToken(username, user.getId(), roles);
        String refreshToken = jwtService.generateRefreshToken(username);

        storedToken.setToken(refreshToken);
        storedToken.setExpiryDate(calculateExpiry());
        refreshTokenRepository.save(storedToken);

        return new RefreshResponseDto(accessToken, refreshToken);
    }

    public Instant calculateExpiry() {
        Date date = jwtService.getRefreshTokenExpiryDate();
        return date.toInstant();
    }
}
