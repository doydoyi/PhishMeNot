package edu.cit.alvarado.phishmenot.auth;

import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import edu.cit.alvarado.phishmenot.common.ApiException;
import edu.cit.alvarado.phishmenot.user.UserDto;

/** Public endpoints for email + password accounts. Each needs the CSRF header like every other POST. */
@RestController
@RequestMapping("/api/auth")
public class LocalAuthController {

    private final LocalAuthService localAuthService;
    private final AuthenticationManager authenticationManager;
    private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();

    public LocalAuthController(LocalAuthService localAuthService, AuthenticationManager authenticationManager) {
        this.localAuthService = localAuthService;
        this.authenticationManager = authenticationManager;
    }

    public record RegisterRequest(
            @NotBlank(message = "Name is required") @Size(max = 150, message = "Name must be at most 150 characters") String name,
            @NotBlank(message = "Email is required") @Email(message = "Enter a valid email address")
            @Size(max = 255, message = "Email must be at most 255 characters") String email,
            @StrongPassword String password,
            @NotBlank(message = "Please confirm your password") String confirmPassword) {}

    public record LoginRequest(
            @NotBlank(message = "Email is required") String email,
            @NotBlank(message = "Password is required") String password) {}

    public record ForgotPasswordRequest(
            @NotBlank(message = "Email is required") @Email(message = "Enter a valid email address") String email) {}

    public record ResetPasswordRequest(
            @NotBlank(message = "Reset token is missing") String token,
            @StrongPassword String newPassword,
            @NotBlank(message = "Please confirm your new password") String confirmPassword) {}

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public UserDto register(@Valid @RequestBody RegisterRequest req) {
        return UserDto.from(localAuthService.register(req.name(), req.email(), req.password(), req.confirmPassword()));
    }

    /** Email + password login. Starts a session exactly like Google sign-in does. */
    @PostMapping("/login")
    public UserDto login(@Valid @RequestBody LoginRequest req, HttpServletRequest request, HttpServletResponse response) {
        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(
                    UsernamePasswordAuthenticationToken.unauthenticated(req.email().trim(), req.password()));
        } catch (AuthenticationException e) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "Invalid email or password.");
        }
        // new session id on login (session fixation protection), then store the authentication in it
        if (request.getSession(false) != null) {
            request.changeSessionId();
        }
        request.getSession(true);
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);
        securityContextRepository.saveContext(context, request, response);
        return UserDto.from(localAuthService.recordLogin(authentication.getName()));
    }

    @PostMapping("/forgot-password")
    public Map<String, String> forgotPassword(@Valid @RequestBody ForgotPasswordRequest req) {
        localAuthService.requestPasswordReset(req.email());
        return Map.of("message",
                "If an account exists for that email, we have sent a password reset link. It expires in "
                        + LocalAuthService.RESET_TOKEN_MINUTES + " minutes.");
    }

    @PostMapping("/reset-password")
    public Map<String, String> resetPassword(@Valid @RequestBody ResetPasswordRequest req) {
        localAuthService.resetPassword(req.token(), req.newPassword(), req.confirmPassword());
        return Map.of("message", "Your password has been reset. You can now sign in with your new password.");
    }
}
