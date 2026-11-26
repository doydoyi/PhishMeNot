package edu.cit.alvarado.phishmenot.verification;

import java.time.LocalDateTime;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

public interface ScanResultRepository extends JpaRepository<ScanResult, Long> {

    /** Newest complete (non-partial) result for a URL checked after {@code since} (24-hour cache, FR-016). */
    Optional<ScanResult> findFirstByUrlHashAndPartialCheckFalseAndCheckedAtAfterOrderByCheckedAtDesc(
            String urlHash, LocalDateTime since);

    /** Latest verdict for a URL, whatever its age (shown to admins next to reports, FR-040). */
    Optional<ScanResult> findFirstByUrlHashOrderByCheckedAtDesc(String urlHash);
}
