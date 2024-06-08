package com.example.SpringSecurityJWT.controllers;

import com.example.SpringSecurityJWT.dto.RequestDTO;
import com.example.SpringSecurityJWT.jwt.JwtUtil;
import com.example.SpringSecurityJWT.service.CustomUserDetailsService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class SecurityController {
    private final CustomUserDetailsService userService;
    private final JwtUtil jwtUtil;

    public SecurityController(CustomUserDetailsService userService, JwtUtil jwtUtil) {
        this.userService = userService;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping(value = "/signup")
    public ResponseEntity<?> signup(@RequestBody RequestDTO signupDTO) {
        return ResponseEntity.ok(userService.createPerson(signupDTO));
    }

    @PostMapping(value = "/signin")
    public ResponseEntity<?> signin(@RequestBody RequestDTO requestDTO) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        UserDetails userDetails = userService.loadUserByUsername(requestDTO.username());
        if (auth.getName().equals(userDetails.getUsername())) {
            String token = jwtUtil.generateToken(userDetails);
            return ResponseEntity.ok(token);
        }
        return ResponseEntity.badRequest().body("NOT VALID");
    }

}
