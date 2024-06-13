package com.example.SpringSecurityJWT.service;

import com.example.SpringSecurityJWT.dto.RequestDTO;
import com.example.SpringSecurityJWT.model.Person;
import com.example.SpringSecurityJWT.repository.UserRepository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


@Service
public class CustomUserDetailsService implements UserDetailsService {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private BlockingService blockingService;
    private static final Logger logger = LoggerFactory.getLogger(CustomUserDetailsService.class);


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        logger.info(String.format("A user named %s logs in", username));
        Person person = userRepository.findByUsername(username)
                .orElseThrow(() -> {
                    logger.warn(String.format("User name %s not found", username));
                    return new UsernameNotFoundException("Person not found");
                });
        if (blockingService.isBlockedPerson(person)) {
            throw new LockedException("Person is blocked");
        }
        return new User(person.getUsername(), person.getPassword(), person.getAuthorities());
    }

    public Person createPerson(RequestDTO signupDTO) {
        Person person = null;
        if (signupDTO.role() == null) {
            person = new Person(
                    signupDTO.username(), passwordEncoder.encode(signupDTO.password()), "ROLE_USER");
            return userRepository.save(person);
        }
        person = new Person(
                signupDTO.username(), passwordEncoder.encode(signupDTO.password()), signupDTO.role());
        return userRepository.save(person);
    }

    public Person findByUsername(String username) {
        return userRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("Person not found"));
    }

    public boolean checkPassword(String requestPassword, String password) {
        return passwordEncoder.matches(requestPassword, password);
    }

    public boolean checkingUserForBlocking(Person person) {
        return blockingService.isBlockedPerson(person);
    }

    public void resetCountAttempt(Person person) {
        blockingService.resetCountAttempt(person);
    }

    public void unsuccessfulAttempt(Person person) {
        blockingService.unsuccessfulAttempt(person);
    }
}
