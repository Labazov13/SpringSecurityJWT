package com.example.SpringSecurityJWT.service;

import com.example.SpringSecurityJWT.model.Person;
import com.example.SpringSecurityJWT.repository.UserRepository;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class BlockingService {

    private final UserRepository userRepository;

    private static final int COUNT_ATTEMPT = 3;
    private static final long TIME_BLOCK_IN_MS = 1_200_000L;

    public BlockingService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public boolean isBlockedPerson(Person user) {
        if (user.isAccountNonLocked()) {
            return false;
        }
        return !unlockPerson(user);
    }

    public void lockPerson(Person user) {
        user.setLocked(true);
        user.setLockTime(new Date());
        userRepository.save(user);
    }


    public boolean unlockPerson(Person user) {
        long lockTime = user.getLockTime().getTime();
        long currentTime = System.currentTimeMillis();
        if (lockTime + TIME_BLOCK_IN_MS < currentTime) {
            user.setLocked(false);
            user.setLockTime(null);
            user.setAttemptEntry(0);
            userRepository.save(user);
            return true;
        }
        return false;
    }


    public void resetCountAttempt(Person user) {
        user.setAttemptEntry(0);
        userRepository.save(user);
    }

    public void unsuccessfulAttempt(Person user) {
        int countFailAttempt = user.getAttemptEntry() + 1;
        user.setAttemptEntry(countFailAttempt);
        if (user.getAttemptEntry() >= COUNT_ATTEMPT) {
            lockPerson(user);
        }
        userRepository.save(user);
    }
}
