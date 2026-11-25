package edu.cit.alvarado.phishmenot.user;

import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import edu.cit.alvarado.phishmenot.auth.PasswordResetTokenRepository;
import edu.cit.alvarado.phishmenot.common.ApiException;

/**
 * Changes to the signed-in user's own account. Callers pass the account resolved from the session,
 * never an id from the request, so one user cannot modify another user's profile.
 */
@Service
public class ProfileService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordResetTokenRepository tokenRepository;

    public ProfileService(UserRepository userRepository, PasswordEncoder passwordEncoder,
            PasswordResetTokenRepository tokenRepository) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenRepository = tokenRepository;
    }

    @Transactional
    public User updateProfile(User user, String name, String profilePictureUrl) {
        user.setName(name.trim());
        user.setProfilePictureUrl(profilePictureUrl == null || profilePictureUrl.isBlank() ? null : profilePictureUrl.trim());
        return userRepository.save(user);
    }

    /** Verifies the current password, then replaces the hash so the old password stops working. */
    @Transactional
    public void changePassword(User user, String currentPassword, String newPassword, String confirmPassword) {
        if (!user.hasPassword()) {
            throw new ApiException(HttpStatus.BAD_REQUEST,
                    "Your account signs in with Google and has no password yet. Use Forgot password on the sign-in page to create one.");
        }
        if (!passwordEncoder.matches(currentPassword, user.getPasswordHash())) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Your current password is incorrect.");
        }
        if (!newPassword.equals(confirmPassword)) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "The new passwords do not match.");
        }
        if (passwordEncoder.matches(newPassword, user.getPasswordHash())) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "Your new password must be different from your current password.");
        }
        user.setPasswordHash(passwordEncoder.encode(newPassword));
        userRepository.save(user);
        tokenRepository.invalidateAllFor(user);
    }
}
