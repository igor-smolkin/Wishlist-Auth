package org.ataraxii.authwishlist.unit;

import org.ataraxii.authwishlist.database.entity.Role;
import org.ataraxii.authwishlist.database.entity.RoleType;
import org.ataraxii.authwishlist.database.entity.User;
import org.ataraxii.authwishlist.database.repository.RoleRepository;
import org.ataraxii.authwishlist.database.repository.UserRepository;
import org.ataraxii.authwishlist.exception.ConflictException;
import org.ataraxii.authwishlist.security.dto.login.LoginRequestDto;
import org.ataraxii.authwishlist.security.dto.login.LoginResponseDto;
import org.ataraxii.authwishlist.security.dto.register.RegisterRequestDto;
import org.ataraxii.authwishlist.security.dto.register.RegisterResponseDto;
import org.ataraxii.authwishlist.security.service.JwtService;
import org.ataraxii.authwishlist.security.service.AuthService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private UserDetailsService userDetailsService;

    @Mock
    private JwtService jwtService;

    @InjectMocks
    private AuthService authService;

    @Test
    void registerUser_valid_save() {
        RegisterRequestDto request = RegisterRequestDto.builder()
                .username("testuser")
                .password("testpassword")
                .build();

        Role roleUser = Role.builder()
                .id(1)
                .name(RoleType.USER)
                .build();

        when(userRepository.existsByUsername(request.getUsername())).thenReturn(false);
        when(roleRepository.findByName(RoleType.USER)).thenReturn(Optional.of(roleUser));
        when(passwordEncoder.encode(request.getPassword())).thenReturn("hashedpassword");

        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);

        RegisterResponseDto response = authService.register(request);

        verify(userRepository).save(userCaptor.capture());
        User savedUser = userCaptor.getValue();

        assertNotNull(response);
        assertEquals("testuser", response.getUsername());

        assertEquals("hashedpassword", savedUser.getPassword());

        assertTrue(savedUser.getRoles().stream()
                .anyMatch(role -> role.getName() == RoleType.USER));
    }

    @Test
    void registerUser_AlreadyExists_throwConflictException() {
        RegisterRequestDto request = RegisterRequestDto.builder()
                .username("testuser")
                .password("testpassword")
                .build();

        when(userRepository.existsByUsername(request.getUsername())).thenReturn(true);
        assertThrows(ConflictException.class, () -> authService.register(request));
    }

    @Test
    void loginUser_valid_returnJwtToken() {
        LoginRequestDto request = LoginRequestDto.builder()
                .username("testuser")
                .password("testpassword")
                .build();

        UserDetails userDetails = mock(UserDetails.class);

        when(authenticationManager.authenticate(any()))
                .thenReturn(new UsernamePasswordAuthenticationToken(userDetails, null, List.of()));
        when(userDetailsService.loadUserByUsername("testuser")).thenReturn(userDetails);
        when(jwtService.generateToken(userDetails)).thenReturn("token.jwt");

        LoginResponseDto response = authService.login(request);

        assertEquals("token.jwt", response.getToken());
    }

    @Test
    void loginUser_wrongUsernameOrPassword_throwUnauthorizedException() {
        LoginRequestDto request = LoginRequestDto.builder()
                .username("wronguser")
                .password("testpassword")
                .build();

        when(authenticationManager.authenticate(any()))
                .thenThrow(new BadCredentialsException("Неверное имя пользователя или пароль"));

        assertThrows(BadCredentialsException.class, () -> authService.login(request));
    }

    @Test
    void loginUser_userIsDisabled_throwUnauthorizedException() {
        LoginRequestDto request = LoginRequestDto.builder()
                .username("disableduser")
                .password("testpassword")
                .build();

        when(authenticationManager.authenticate(any()))
                .thenThrow(new DisabledException("Пользователь деактивирован"));

        assertThrows(DisabledException.class, () -> authService.login(request));
    }
}
