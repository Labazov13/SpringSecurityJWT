package com.example.SpringSecurityJWT.jwt;

import com.example.SpringSecurityJWT.configuration.AppProperties;
import com.example.SpringSecurityJWT.service.CustomUserDetailsService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.stream.Collectors;

@Component
public class JwtUtil {
    @Autowired
    private AppProperties appProperties;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private CustomUserDetailsService userDetailsService;



    public String generateToken(UserDetails userDetails) {
        return Jwts.builder()
                .setSubject(userDetails.getUsername())
                .claim("role", userDetails.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList()))
                .setIssuedAt(new Date()).setExpiration(new Date((new Date()).getTime() + appProperties.getExpiration()))
                .signWith(SignatureAlgorithm.HS256, appProperties.getSecret())
                .compact();
    }


    public String getNameFromJwt(String token) {
        return Jwts.parser().setSigningKey(appProperties.getSecret()).parseClaimsJws(token).getBody().getSubject();
    }

    public Authentication createAuthentication(String token) {
        String username = getNameFromJwt(token);
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        return new UsernamePasswordAuthenticationToken(userDetails.getUsername(), "", userDetails.getAuthorities());
    }
    public boolean validateToken(String token) {
        Claims claims = Jwts.parser().setSigningKey(appProperties.getSecret()).parseClaimsJws(token).getBody();
        Date expirationDate = claims.getExpiration();
        return !expirationDate.before(new Date());
    }

    public UserDetails extractUserDetailsFromToken(String token) {
        Claims claims = Jwts.parser().setSigningKey(appProperties.getSecret()).parseClaimsJws(token).getBody();
        String username = claims.get("sub", String.class);
        return userDetailsService.loadUserByUsername(username);
    }
}