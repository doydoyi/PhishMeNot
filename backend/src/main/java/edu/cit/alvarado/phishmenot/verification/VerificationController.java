package edu.cit.alvarado.phishmenot.verification;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import edu.cit.alvarado.phishmenot.auth.CurrentUserService;

/** Link checks and the signed-in user's own verification history. */
@RestController
@RequestMapping("/api/verifications")
public class VerificationController {

    private final VerificationService verificationService;
    private final CurrentUserService currentUserService;

    public VerificationController(VerificationService verificationService, CurrentUserService currentUserService) {
        this.verificationService = verificationService;
        this.currentUserService = currentUserService;
    }

    public record VerifyRequest(
            @NotBlank(message = "Please enter a link to check")
            @Size(max = UrlNormalizer.MAX_LENGTH, message = "This link is too long (maximum 2048 characters)") String url) {}

    @PostMapping
    public VerificationDto verify(@Valid @RequestBody VerifyRequest req, Authentication authentication) {
        return verificationService.verify(currentUserService.require(authentication), req.url());
    }

    @GetMapping
    public VerificationService.HistoryPage history(@RequestParam(required = false) Verdict verdict,
            @RequestParam(defaultValue = "") String query,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            Authentication authentication) {
        return verificationService.history(currentUserService.require(authentication), verdict, query, page, size);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@PathVariable Long id, Authentication authentication) {
        verificationService.deleteHistoryEntry(currentUserService.require(authentication), id);
    }
}
