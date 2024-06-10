package com.example.SpringSecurityJWT.jwt;

import com.example.SpringSecurityJWT.configuration.AppProperties;
import com.example.SpringSecurityJWT.service.CustomUserDetails;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Date;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    @Autowired
    private JwtUtil jwtUtil = new JwtUtil();
    @Autowired
    private AppProperties appProperties = new AppProperties();
    public String getSecret(){
        return appProperties.getSecret();
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String token = extractTokenFromRequest(request);
        if (token != null && validateToken(token)) {
            Authentication auth = createAuthentication(token);
            SecurityContextHolder.getContext().setAuthentication(auth);
        }
        filterChain.doFilter(request, response);
    }

    public String extractTokenFromRequest(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");
        if (headerAuth != null && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7);
        }
        return null;
    }

    public boolean validateToken(String token) {
        String secret = getSecret();
        Claims claims = Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
        Date expirationDate = claims.getExpiration();
        return !expirationDate.before(new Date());
    }

    public Authentication createAuthentication(String token) {
        // Логика создания объекта Authentication на основе токена
        CustomUserDetails userDetails = extractUserDetailsFromToken(token);
        return new JwtAuthenticationToken(userDetails, token, userDetails.getAuthorities());
    }
    public CustomUserDetails extractUserDetailsFromToken(String token) {
        // Логика извлечения информации о пользователе из токена
        return jwtUtil.extractUserDetailsFromToken(token);
    }
}
