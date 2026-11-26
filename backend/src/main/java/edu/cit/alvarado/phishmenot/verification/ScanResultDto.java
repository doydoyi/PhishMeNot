package edu.cit.alvarado.phishmenot.verification;

import java.time.LocalDateTime;
import java.util.List;

/** A scan result without a user (admin re-check, FR-043). */
public record ScanResultDto(String normalizedUrl, Verdict verdict, String explanation, List<String> threatTypes,
        Integer vtMaliciousCount, Integer vtSuspiciousCount, Integer vtTotalEngines, boolean partialCheck,
        LocalDateTime checkedAt) {

    public static ScanResultDto from(ScanResult r, VerdictEngine engine) {
        return new ScanResultDto(r.getNormalizedUrl(), r.getVerdict(), engine.explain(r), r.threatTypes(),
                r.getVtMaliciousCount(), r.getVtSuspiciousCount(), r.getVtTotalEngines(), r.isPartialCheck(),
                r.getCheckedAt());
    }
}
