package edu.cit.alvarado.phishmenot.verification;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import edu.cit.alvarado.phishmenot.user.User;

public interface VerificationRepository extends JpaRepository<Verification, Long> {

    long countByUserAndCreatedAtAfter(User user, LocalDateTime since);

    Optional<Verification> findByVerificationIdAndUser(Long verificationId, User user);

    /** A user's own history, newest first, optionally filtered by verdict and URL text (FR-023, FR-024). */
    @Query(value = """
            select v from Verification v join fetch v.scanResult s
            where v.user = :user
              and (:verdict is null or s.verdict = :verdict)
              and (:q = '' or lower(v.submittedUrl) like concat('%', :q, '%') or lower(s.normalizedUrl) like concat('%', :q, '%'))
            order by v.createdAt desc, v.verificationId desc""",
            countQuery = """
            select count(v) from Verification v join v.scanResult s
            where v.user = :user
              and (:verdict is null or s.verdict = :verdict)
              and (:q = '' or lower(v.submittedUrl) like concat('%', :q, '%') or lower(s.normalizedUrl) like concat('%', :q, '%'))""")
    Page<Verification> searchHistory(User user, Verdict verdict, String q, Pageable pageable);

    @Query("select s.verdict, count(v) from Verification v join v.scanResult s group by s.verdict")
    List<Object[]> countByVerdict();

    @Query("select v.createdAt from Verification v where v.createdAt >= :since")
    List<LocalDateTime> findCreatedAtSince(LocalDateTime since);
}
