package edu.cit.alvarado.phishmenot.verification;

import java.time.LocalDateTime;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Supplier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import edu.cit.alvarado.phishmenot.common.ApiException;
import edu.cit.alvarado.phishmenot.user.User;

/** Link verification and history (Features 1-3 of the SRS). */
@Service
public class VerificationService {

    private static final Logger log = LoggerFactory.getLogger(VerificationService.class);
    public static final int MAX_PAGE_SIZE = 50;

    private final UrlNormalizer normalizer;
    private final VerdictEngine engine;
    private final SafeBrowsingClient safeBrowsing;
    private final VirusTotalClient virusTotal;
    private final ScanResultRepository scanResults;
    private final VerificationRepository verifications;
    private final int hourlyLimit;
    private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();

    public VerificationService(UrlNormalizer normalizer, VerdictEngine engine, SafeBrowsingClient safeBrowsing,
            VirusTotalClient virusTotal, ScanResultRepository scanResults, VerificationRepository verifications,
            @Value("${app.verification.hourly-limit:20}") int hourlyLimit) {
        this.normalizer = normalizer;
        this.engine = engine;
        this.safeBrowsing = safeBrowsing;
        this.virusTotal = virusTotal;
        this.scanResults = scanResults;
        this.verifications = verifications;
        this.hourlyLimit = hourlyLimit;
    }

    public record HistoryPage(List<VerificationDto> items, int page, int size, long totalElements, int totalPages) {}

    /**
     * Verifies a link for a user: validates and normalizes it, enforces the hourly limit (FR-018), reuses a
     * complete result from the last 24 hours (FR-016) or checks both services, and saves it to their history.
     */
    public VerificationDto verify(User user, String submittedUrl) {
        String normalized = normalizer.normalize(submittedUrl);
        String hash = normalizer.hash(normalized);
        LocalDateTime now = LocalDateTime.now();
        if (verifications.countByUserAndCreatedAtAfter(user, now.minusHours(1)) >= hourlyLimit) {
            throw new ApiException(HttpStatus.TOO_MANY_REQUESTS, "You have reached the limit of " + hourlyLimit
                    + " link checks per hour. Please try again later.");
        }
        ScanResult result = scanResults
                .findFirstByUrlHashAndPartialCheckFalseAndCheckedAtAfterOrderByCheckedAtDesc(hash, now.minusHours(ScanResult.FRESH_HOURS))
                .orElse(null);
        boolean cached = result != null;
        if (!cached) {
            result = scan(normalized, hash);
        }
        Verification saved = verifications.save(new Verification(user, result, submittedUrl.trim()));
        return VerificationDto.from(saved, engine, cached);
    }

    /**
     * Checks a normalized URL against both services in parallel and stores the combined result. If one
     * service fails the other's answer is used and marked partial (FR-017); if both fail the user gets 503.
     */
    public ScanResult scan(String normalizedUrl, String urlHash) {
        CompletableFuture<SafeBrowsingResult> gsb = CompletableFuture.supplyAsync(
                () -> safely("Google Safe Browsing", () -> safeBrowsing.check(normalizedUrl)), executor);
        CompletableFuture<VirusTotalResult> vt = CompletableFuture.supplyAsync(
                () -> safely("VirusTotal", () -> virusTotal.check(normalizedUrl)), executor);
        SafeBrowsingResult gsbResult = gsb.join();
        VirusTotalResult vtResult = vt.join();
        if (gsbResult == null && vtResult == null) {
            throw new ApiException(HttpStatus.SERVICE_UNAVAILABLE,
                    "We could not reach the threat-checking services right now. Please try again in a few minutes.");
        }
        return scanResults.save(new ScanResult(normalizedUrl, urlHash, engine.decide(gsbResult, vtResult), gsbResult, vtResult));
    }

    private static <T> T safely(String service, Supplier<T> call) {
        try {
            return call.get();
        } catch (RuntimeException e) {
            // NFR-016: technical details go to the server log only
            log.warn("{} check failed: {}", service, e.getMessage());
            return null;
        }
    }

    @Transactional(readOnly = true)
    public HistoryPage history(User user, Verdict verdict, String query, int page, int size) {
        if (page < 0 || size < 1) {
            throw new IllegalArgumentException("page must be >= 0 and size >= 1");
        }
        String q = query == null ? "" : query.trim().toLowerCase();
        var result = verifications.searchHistory(user, verdict, q, PageRequest.of(page, Math.min(size, MAX_PAGE_SIZE)))
                .map(v -> VerificationDto.from(v, engine, false));
        return new HistoryPage(result.getContent(), result.getNumber(), result.getSize(), result.getTotalElements(),
                result.getTotalPages());
    }

    /** Deletes one entry of the user's own history (FR-025). Other users' entries are reported as not found. */
    @Transactional
    public void deleteHistoryEntry(User user, Long verificationId) {
        Verification v = verifications.findByVerificationIdAndUser(verificationId, user)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "This history entry was not found."));
        verifications.delete(v);
    }
}
