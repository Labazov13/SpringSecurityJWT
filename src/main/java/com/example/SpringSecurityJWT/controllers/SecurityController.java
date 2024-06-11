package com.example.SpringSecurityJWT.controllers;

import com.example.SpringSecurityJWT.dto.RequestDTO;
import com.example.SpringSecurityJWT.jwt.JwtUtil;
import com.example.SpringSecurityJWT.model.Person;
import com.example.SpringSecurityJWT.repository.UserRepository;
import com.example.SpringSecurityJWT.service.CustomUserDetailsService;
import com.example.SpringSecurityJWT.views.Views;
import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.http.ResponseEntity;
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
    private final UserRepository repository;

    public SecurityController(CustomUserDetailsService userService, JwtUtil jwtUtil, UserRepository repository) {
        this.userService = userService;
        this.jwtUtil = jwtUtil;
        this.repository = repository;
    }

    @PostMapping(value = "/signup")
    @JsonView(Views.PersonSummary.class)
    public ResponseEntity<?> signup(@RequestBody RequestDTO signupDTO) {
        return ResponseEntity.ok(userService.createPerson(signupDTO));
    }

    @PostMapping(value = "/signin")
    public ResponseEntity<?> signin(@RequestBody RequestDTO requestDTO) {
        Person person = userService.findByUsername(requestDTO.username());
        UserDetails userDetails = userService.loadUserByUsername(requestDTO.username());
        if (userDetails.getUsername().equals(person.getUsername())) {
            String token = jwtUtil.generateToken(userDetails);
            return ResponseEntity.ok(token);
        }
        return ResponseEntity.badRequest().body("NOT VALID");
    }

}
