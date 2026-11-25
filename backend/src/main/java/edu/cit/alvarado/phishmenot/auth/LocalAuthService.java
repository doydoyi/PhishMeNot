package edu.cit.alvarado.phishmenot.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Locale;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import edu.cit.alvarado.phishmenot.common.ApiException;
import edu.cit.alvarado.phishmenot.config.AppProperties;
import edu.cit.alvarado.phishmenot.user.Role;
import edu.cit.alvarado.phishmenot.user.User;
import edu.cit.alvarado.phishmenot.user.UserRepository;

/** Email + password accounts: registration, login bookkeeping, and forgot/reset password. */
@Service
public class LocalAuthService {

    private static final Logger log = LoggerFactory.getLogger(LocalAuthService.class);
    static final long RESET_TOKEN_MINUTES = 30;

    private final UserRepository userRepository;
    private final PasswordResetTokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordResetMailer mailer;
    private final AppProperties appProperties;
    private final SecureRandom random = new SecureRandom();

    public LocalAuthService(UserRepository userRepository, PasswordResetTokenRepository tokenRepository,
            PasswordEncoder passwordEncoder, PasswordResetMailer mailer, AppProperties appProperties) {
        this.userRepository = userRepository;
        this.tokenRepository = tokenRepository;
        this.passwordEncoder = passwordEncoder;
        this.mailer = mailer;
        this.appProperties = appProperties;
    }

    /**
     * Creates a General User account with a BCrypt-hashed password. An email that is already registered
     * (with Google or a password) is rejected rather than merged, so nobody can pre-register someone
     * else's email. ADMIN_EMAILS is deliberately not applied: this email has not been verified.
     */
    @Transactional
    public User register(String name, String email, String password, String confirmPassword) {
        requireMatch(password, confirmPassword);
        String normalized = normalizeEmail(email);
        if (userRepository.findByEmailIgnoreCase(normalized).isPresent()) {
            throw new ApiException(HttpStatus.CONFLICT,
                    "An account with this email already exists. Sign in instead, or use Forgot password.");
        }
        User user = new User(null, normalized, name.trim(), null, Role.USER);
        user.setPasswordHash(passwordEncoder.encode(password));
        try {
            User saved = userRepository.saveAndFlush(user);
            log.info("Registered new password account id={}", saved.getUserId());
            return saved;
        } catch (DataIntegrityViolationException e) {
            throw new ApiException(HttpStatus.CONFLICT, "An account with this email already exists.");
        }
    }

    @Transactional
    public User recordLogin(String email) {
        User user = userRepository.findByEmailIgnoreCase(email)
                .orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "Invalid email or password."));
        user.setLastLoginAt(LocalDateTime.now());
        return user;
    }

    /**
     * Emails a reset link if the address belongs to an account. The caller always answers the same way,
     * so the response does not reveal which emails are registered.
     */
    @Transactional
    public void requestPasswordReset(String email) {
        User user = userRepository.findByEmailIgnoreCase(normalizeEmail(email)).orElse(null);
        if (user == null) {
            log.info("Password reset requested for an unknown email");
            return;
        }
        tokenRepository.invalidateAllFor(user);
        String rawToken = newToken();
        tokenRepository.save(new PasswordResetToken(user, sha256(rawToken),
                LocalDateTime.now().plusMinutes(RESET_TOKEN_MINUTES)));
        String link = appProperties.frontendUrl() + "/reset-password?token=" + rawToken;
        mailer.sendResetLink(user.getEmail(), user.getName(), link, RESET_TOKEN_MINUTES);
    }

    /** Sets a new password using a valid reset token, then burns the token (single use). */
    @Transactional
    public void resetPassword(String rawToken, String newPassword, String confirmPassword) {
        requireMatch(newPassword, confirmPassword);
        LocalDateTime now = LocalDateTime.now();
        PasswordResetToken token = tokenRepository.findByTokenHash(sha256(rawToken.trim()))
                .filter(t -> t.isUsable(now))
                .orElseThrow(() -> new ApiException(HttpStatus.BAD_REQUEST,
                        "This reset link is invalid, has expired, or was already used. Request a new one."));
        User user = token.getUser();
        user.setPasswordHash(passwordEncoder.encode(newPassword));
        token.markUsed(now);
        tokenRepository.invalidateAllFor(user);
        log.info("Password reset completed for account id={}", user.getUserId());
    }

    static void requireMatch(String password, String confirmPassword) {
        if (!password.equals(confirmPassword)) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "The passwords do not match.");
        }
    }

    private static String normalizeEmail(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }

    private String newToken() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
