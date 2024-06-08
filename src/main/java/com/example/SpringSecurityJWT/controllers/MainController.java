package com.example.SpringSecurityJWT.controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/secured")
public class MainController {
    @GetMapping(value = "/user")
    public ResponseEntity<String> getInfo(Principal principal){
        return ResponseEntity.ok(principal.getName());
    }
}
