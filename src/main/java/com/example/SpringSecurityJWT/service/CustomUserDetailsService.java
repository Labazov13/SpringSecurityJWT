package com.example.SpringSecurityJWT.service;

import com.example.SpringSecurityJWT.dto.RequestDTO;
import com.example.SpringSecurityJWT.model.Person;
import com.example.SpringSecurityJWT.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class CustomUserDetailsService implements UserDetailsService {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;


    @Override
    public CustomUserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<Person> person = userRepository.findByUsername(username);
        try {
            return person.map(CustomUserDetails::new).orElseThrow(Exception::new);
        } catch (Exception e) {
            throw new UsernameNotFoundException("Person not found");
        }
    }

    public Person createPerson(RequestDTO signupDTO) {
        Person person = new Person(signupDTO.username(), passwordEncoder.encode(signupDTO.password()), "ROLE_USER");
        return userRepository.save(person);
    }

    public Person findByUsername(String username){
        return userRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("Person not found"));
    }
}
