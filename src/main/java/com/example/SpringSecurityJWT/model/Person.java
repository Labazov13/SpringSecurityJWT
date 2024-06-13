package com.example.SpringSecurityJWT.model;

import com.example.SpringSecurityJWT.views.Views;
import com.fasterxml.jackson.annotation.JsonView;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;
import java.util.Date;

@Data
@Entity
@Table(name = "persons_table")
@AllArgsConstructor
@NoArgsConstructor
public class Person implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @JsonView(Views.PersonSummary.class)
    private Long id;
    @JsonView(Views.PersonSummary.class)
    private String username;
    private String password;
    private String role;
    @Column(name = "block")
    private boolean isLocked;
    @Column(name = "block_time")
    private Date lockTime;
    @Column(name = "attempt_entry")
    private int attemptEntry;

    public Person(String username, String password, String role) {
        this.username = username;
        this.password = password;
        this.role = role;
    }

    public Person(String username, String password, String role, boolean isLocked, Date lockTime, int attemptEntry) {
        this.username = username;
        this.password = password;
        this.role = role;
        this.isLocked = isLocked;
        this.lockTime = lockTime;
        this.attemptEntry = attemptEntry;
    }
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singleton(new SimpleGrantedAuthority(role));
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return !isLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
