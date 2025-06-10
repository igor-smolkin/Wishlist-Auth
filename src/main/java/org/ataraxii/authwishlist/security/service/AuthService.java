package org.ataraxii.authwishlist.security.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.ataraxii.authwishlist.database.entity.Role;
import org.ataraxii.authwishlist.database.entity.RoleType;
import org.ataraxii.authwishlist.database.entity.User;
import org.ataraxii.authwishlist.database.repository.RoleRepository;
import org.ataraxii.authwishlist.database.repository.UserRepository;
import org.ataraxii.authwishlist.exception.ConflictException;
import org.ataraxii.authwishlist.exception.NotFoundException;
import org.ataraxii.authwishlist.security.dto.login.LoginRequestDto;
import org.ataraxii.authwishlist.security.dto.login.LoginResponseDto;
import org.ataraxii.authwishlist.security.dto.register.RegisterRequestDto;
import org.ataraxii.authwishlist.security.dto.register.RegisterResponseDto;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RoleRepository roleRepository;
    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final JwtService jwtService;

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

            UserDetails userDetails = userDetailsService.loadUserByUsername(request.getUsername());

            String jwtToken = jwtService.generateToken(userDetails);
            log.info("Успешный вход: username='{}'", request.getUsername());
            return new LoginResponseDto(jwtToken);
        } catch (BadCredentialsException e) {
            log.warn("Ошибка входа: username='{}' неверный логин или пароль", request.getUsername());
            throw e;
        } catch (DisabledException e) {
            log.warn("Ошибка входа: username='{}' пользователь деактивирован", request.getUsername());
            throw e;
        }
    }
}
