package com.example.SpringSecurityJWT.model;

import com.example.SpringSecurityJWT.views.Views;
import com.fasterxml.jackson.annotation.JsonView;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Entity
@Table(name = "persons_table")
@AllArgsConstructor
@NoArgsConstructor
public class Person {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @JsonView(Views.PersonSummary.class)
    private Long id;
    @JsonView(Views.PersonSummary.class)
    private String username;
    private String password;
    private String role;

    public Person(String username, String password, String role) {
        this.username = username;
        this.password = password;
        this.role = role;
    }
}
