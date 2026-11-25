package edu.cit.alvarado.phishmenot.user;

import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import edu.cit.alvarado.phishmenot.auth.CurrentUserService;
import edu.cit.alvarado.phishmenot.auth.StrongPassword;

/**
 * The signed-in user's own profile ({@code GET /api/me} is in AuthController). There is no user id in
 * these URLs or bodies: the account always comes from the session.
 */
@RestController
@RequestMapping("/api/me")
public class ProfileController {

    private final CurrentUserService currentUserService;
    private final ProfileService profileService;

    public ProfileController(CurrentUserService currentUserService, ProfileService profileService) {
        this.currentUserService = currentUserService;
        this.profileService = profileService;
    }

    public record UpdateProfileRequest(
            @NotBlank(message = "Name is required") @Size(max = 150, message = "Name must be at most 150 characters") String name,
            @Size(max = 500, message = "Picture URL must be at most 500 characters")
            @Pattern(regexp = "^$|^https://\\S+$", message = "Picture URL must start with https://") String profilePictureUrl) {}

    public record ChangePasswordRequest(
            @NotBlank(message = "Current password is required") String currentPassword,
            @StrongPassword String newPassword,
            @NotBlank(message = "Please confirm your new password") String confirmPassword) {}

    @PutMapping("/profile")
    public UserDto updateProfile(@Valid @RequestBody UpdateProfileRequest req, Authentication authentication) {
        User user = currentUserService.require(authentication);
        return UserDto.from(profileService.updateProfile(user, req.name(), req.profilePictureUrl()));
    }

    @PutMapping("/password")
    public Map<String, String> changePassword(@Valid @RequestBody ChangePasswordRequest req,
            Authentication authentication, HttpServletRequest request) {
        User user = currentUserService.require(authentication);
        profileService.changePassword(user, req.currentPassword(), req.newPassword(), req.confirmPassword());
        request.changeSessionId();
        return Map.of("message", "Your password has been changed. Use your new password the next time you sign in.");
    }
}
