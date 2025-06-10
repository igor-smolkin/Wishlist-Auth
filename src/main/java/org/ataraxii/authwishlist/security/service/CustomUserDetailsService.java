package org.ataraxii.authwishlist.security.service;

import lombok.RequiredArgsConstructor;
import org.ataraxii.authwishlist.exception.NotFoundException;
import org.ataraxii.authwishlist.security.adapter.CustomUserDetails;
import org.ataraxii.authwishlist.database.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByUsername(username)
                .map(CustomUserDetails::new)
                .orElseThrow(() -> new NotFoundException("Пользователь с таким именем не найден"));
    }
}
