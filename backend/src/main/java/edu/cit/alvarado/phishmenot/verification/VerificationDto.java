package edu.cit.alvarado.phishmenot.verification;

import java.time.LocalDateTime;
import java.util.List;

/**
 * One verification as shown to its owner: verdict, plain-language explanation and safety tips.
 * {@code cached} is true when a result from the last 24 hours was reused.
 */
public record VerificationDto(
        Long id,
        String submittedUrl,
        String normalizedUrl,
        Verdict verdict,
        String explanation,
        List<String> safetyTips,
        List<String> threatTypes,
        Integer vtMaliciousCount,
        Integer vtSuspiciousCount,
        Integer vtTotalEngines,
        boolean partialCheck,
        boolean cached,
        LocalDateTime checkedAt,
        LocalDateTime createdAt) {

    static VerificationDto from(Verification v, VerdictEngine engine, boolean cached) {
        ScanResult r = v.getScanResult();
        return new VerificationDto(v.getVerificationId(), v.getSubmittedUrl(), r.getNormalizedUrl(), r.getVerdict(),
                engine.explain(r), engine.safetyTips(r.getVerdict()), r.threatTypes(), r.getVtMaliciousCount(),
                r.getVtSuspiciousCount(), r.getVtTotalEngines(), r.isPartialCheck(), cached, r.getCheckedAt(),
                v.getCreatedAt());
    }
}
