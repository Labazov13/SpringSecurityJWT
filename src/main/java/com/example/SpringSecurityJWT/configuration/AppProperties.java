package com.example.SpringSecurityJWT.configuration;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@ConfigurationProperties(prefix = "testing.app")
public class AppProperties {
    private String secret;
    private int expiration;
}
