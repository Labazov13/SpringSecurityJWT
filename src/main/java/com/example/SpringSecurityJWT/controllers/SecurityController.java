package com.example.SpringSecurityJWT.controllers;

import com.example.SpringSecurityJWT.dto.RequestDTO;
import com.example.SpringSecurityJWT.jwt.JwtUtil;
import com.example.SpringSecurityJWT.model.Person;
import com.example.SpringSecurityJWT.service.CustomUserDetailsService;
import com.example.SpringSecurityJWT.views.Views;
import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class SecurityController {
    private final AuthenticationManager authenticationManager;
    private final CustomUserDetailsService userService;
    private final JwtUtil jwtUtil;

    public SecurityController(AuthenticationManager authenticationManager,
                              CustomUserDetailsService userService,
                              JwtUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.userService = userService;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping(value = "/signup", produces = MediaType.APPLICATION_JSON_VALUE)
    @JsonView(Views.PersonSummary.class)
    public ResponseEntity<?> signup(@RequestBody RequestDTO signupDTO) {
        return ResponseEntity.ok(userService.createPerson(signupDTO));
    }

    @PostMapping(value = "/signin", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> signin(@RequestBody RequestDTO requestDTO) {
        Person person = userService.findByUsername(requestDTO.username());
        if (userService.checkingUserForBlocking(person)) {
            return ResponseEntity.badRequest().body("Account blocked for 20 minutes");
        }
        if (userService.checkPassword(requestDTO.password(), person.getPassword())) {
            Authentication authentication = authenticationManager.
                    authenticate(new UsernamePasswordAuthenticationToken(person.getUsername(),
                            person.getPassword(), person.getAuthorities()));
            SecurityContextHolder.getContext().setAuthentication(authentication);
            String token = jwtUtil.generateToken(person);
            userService.resetCountAttempt(person);
            return ResponseEntity.ok(token);
        }
        userService.unsuccessfulAttempt(person);
        return ResponseEntity.status(401).body("Invalid password");
    }
}

