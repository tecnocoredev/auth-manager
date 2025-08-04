package com.tecnocore.secure.service;

import com.tecnocore.secure.dto.*;
import com.tecnocore.secure.entity.Role;
import com.tecnocore.secure.entity.User;
import com.tecnocore.secure.exception.UserAlreadyExistsException;
import com.tecnocore.secure.repository.RoleRepository;
import com.tecnocore.secure.repository.UserRepository;
import com.tecnocore.secure.security.JwtTokenProvider;
import com.tecnocore.secure.util.UtilDate;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class AuthService implements UserDetailsService {

    private final UserRepository userRepo;
    private final RoleRepository roleRepo;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;

    @Transactional
    public RegisterResponse register(RegisterRequest req) {
        if (userRepo.findByEmail(req.getEmail()).isPresent()) {
            throw new UserAlreadyExistsException("El correo electrónico '" + req.getEmail() + "' ya está registrado.");
        }

        Role role = roleRepo.findByName("ROLE_USER")
                .orElseThrow(() -> new RuntimeException("Rol USER no encontrado"));

        User user = new User();
        user.setEmail(req.getEmail());
        user.setUsername(req.getName());
        user.setPassword(passwordEncoder.encode(req.getPassword()));
        user.setRole(role);

        userRepo.save(user);
        RegisterResponse response = new RegisterResponse();
        response.setMessage("Usuario "+user.getUsername()+" registrado exitosamente!.");
        response.setStatus(HttpStatus.CREATED.value());
        response.setTimestamp(UtilDate.formatDateTime(LocalDateTime.now()));
        return response;
    }

    public JwtResponse generateTokensForAuthenticatedUser(Authentication authentication) {
        String accessToken = jwtTokenProvider.generateAccessToken(authentication);
        String refreshToken = jwtTokenProvider.generateRefreshToken(authentication);
        return new JwtResponse(accessToken, refreshToken, "Bearer");
    }

    public UserDTO getCurrentUser(String email) {
        User user = userRepo.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));

        return new UserDTO(user.getEmail(), user.getUsername());
    }

    public JwtResponse refreshToken(RefreshTokenRequest req) {
        if (!jwtTokenProvider.validateToken(req.getRefreshToken())) {
            throw new RuntimeException("Refresh token inválido o expirado");
        }

        String email = jwtTokenProvider.getEmailFromToken(req.getRefreshToken());

        UserDetails user = loadUserByUsername(email);
        org.springframework.security.authentication.UsernamePasswordAuthenticationToken auth =
                new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());


        String newAccessToken = jwtTokenProvider.generateAccessToken(auth);
        String newRefreshToken = jwtTokenProvider.generateRefreshToken(auth);

        return new JwtResponse(newAccessToken, newRefreshToken, "Bearer");
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepo.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));

        return org.springframework.security.core.userdetails.User
                .withUsername(user.getEmail())
                .password(user.getPassword())
                .authorities(user.getRole().getName())
                .build();
    }
}
