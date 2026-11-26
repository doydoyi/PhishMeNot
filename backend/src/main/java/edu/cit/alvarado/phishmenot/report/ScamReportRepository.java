package edu.cit.alvarado.phishmenot.report;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import edu.cit.alvarado.phishmenot.user.User;

public interface ScamReportRepository extends JpaRepository<ScamReport, Long> {

    boolean existsByReporterAndUrlHash(User reporter, String urlHash);

    List<ScamReport> findByReporterOrderByCreatedAtDesc(User reporter);

    @Query("select r from ScamReport r join fetch r.reporter left join fetch r.reviewedBy where r.status = :status order by r.createdAt asc")
    List<ScamReport> findByStatusWithPeople(ReportStatus status);

    /** Approved reports for the public list, optionally filtered by URL text and category (FR-032, FR-034). */
    @Query("""
            select r from ScamReport r
            where r.status = edu.cit.alvarado.phishmenot.report.ReportStatus.APPROVED
              and (:category is null or r.category = :category)
              and (:q = '' or lower(r.normalizedUrl) like concat('%', :q, '%'))
            order by r.reviewedAt desc""")
    List<ScamReport> findApproved(ReportCategory category, String q);

    @Query("select r.status, count(r) from ScamReport r group by r.status")
    List<Object[]> countByStatus();
}
