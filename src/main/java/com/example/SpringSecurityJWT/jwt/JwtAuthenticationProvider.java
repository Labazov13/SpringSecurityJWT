package com.example.SpringSecurityJWT.jwt;

import com.example.SpringSecurityJWT.model.Person;
import com.example.SpringSecurityJWT.repository.UserRepository;
import com.example.SpringSecurityJWT.service.CustomUserDetails;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Component
public class JwtAuthenticationProvider implements AuthenticationProvider {
    @Autowired
    private JwtUtil jwtUtil;
    @Autowired
    private UserRepository userRepository;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();
        Person person = userRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("Not found"));
        if (!password.equals(person.getPassword())){
            throw new BadCredentialsException("Invalid password");
        }
        CustomUserDetails userDetails = (CustomUserDetails) User.builder()
                .username(person.getUsername())
                .password(person.getPassword())
                .roles(person.getRole()).build();
        return new JwtAuthenticationToken(userDetails, password, userDetails.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
