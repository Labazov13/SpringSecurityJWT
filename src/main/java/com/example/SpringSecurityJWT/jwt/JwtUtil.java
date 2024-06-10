package com.example.SpringSecurityJWT.jwt;

import com.example.SpringSecurityJWT.configuration.AppProperties;
import com.example.SpringSecurityJWT.service.CustomUserDetails;
import com.example.SpringSecurityJWT.service.CustomUserDetailsService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
@Data
public class JwtUtil {
    @Autowired
    private AppProperties appProperties = new AppProperties();
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private CustomUserDetailsService userDetailsService;

    public String getSecret() {
        return appProperties.getSecret();
    }

    public int getExpiration() {
        return appProperties.getExpiration();
    }


    public String generateToken(UserDetails userDetails) {
        return Jwts.builder().setSubject(userDetails.getUsername())
                .setIssuedAt(new Date()).setExpiration(new Date((new Date()).getTime() + getExpiration()))
                .signWith(SignatureAlgorithm.HS256, getSecret())
                .compact();

    }


    public String getNameFromJwt(String token) {
        return Jwts.parser().setSigningKey(getSecret()).parseClaimsJws(token).getBody().getSubject();
    }

    public Authentication createAuthentication(String token) {
        // Получение информации о пользователе из токена
        String username = getNameFromJwt(token);
        CustomUserDetails userDetails = userDetailsService.loadUserByUsername(username);
        // Создание объекта Authentication
        return authenticationManager.authenticate(new JwtAuthenticationToken(userDetails, token, userDetails.getAuthorities()));
    }

    public boolean validateToken(String token) {
        // Логика верификации токена
        Claims claims = Jwts.parser().setSigningKey(getSecret()).parseClaimsJws(token).getBody();
        Date expirationDate = claims.getExpiration();
        return !expirationDate.before(new Date());
    }

    public CustomUserDetails extractUserDetailsFromToken(String token) {
        // Логика извлечения информации о пользователе из токена
        Claims claims = Jwts.parser().setSigningKey(getSecret()).parseClaimsJws(token).getBody();
        String username = claims.get("username", String.class);
        return userDetailsService.loadUserByUsername(username);
    }
}
