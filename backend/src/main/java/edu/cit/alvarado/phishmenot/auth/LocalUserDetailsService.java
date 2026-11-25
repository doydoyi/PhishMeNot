package edu.cit.alvarado.phishmenot.auth;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import edu.cit.alvarado.phishmenot.user.User;
import edu.cit.alvarado.phishmenot.user.UserRepository;

/** Loads an account for email + password login. Google-only accounts (no password) cannot log in this way. */
@Service
public class LocalUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public LocalUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String email) {
        User user = userRepository.findByEmailIgnoreCase(email.trim())
                .filter(User::hasPassword)
                .orElseThrow(() -> new UsernameNotFoundException("No password account for this email"));
        return org.springframework.security.core.userdetails.User.withUsername(user.getEmail())
                .password(user.getPasswordHash())
                .authorities(user.getRole().authority())
                .build();
    }
}
