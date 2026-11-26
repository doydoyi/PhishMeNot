package edu.cit.alvarado.phishmenot.report;

import java.time.LocalDateTime;

import edu.cit.alvarado.phishmenot.verification.ScanResult;
import edu.cit.alvarado.phishmenot.verification.Verdict;

/** JSON views of scam reports for the reporter, the public, and administrators. */
public final class ReportDtos {

    private ReportDtos() {
    }

    /** A report as its reporter sees it (FR-036). */
    public record MyReportDto(Long id, String url, ReportCategory category, String description, ReportStatus status,
            LocalDateTime createdAt, LocalDateTime reviewedAt) {

        static MyReportDto from(ScamReport r) {
            return new MyReportDto(r.getReportId(), r.getNormalizedUrl(), r.getCategory(), r.getDescription(),
                    r.getStatus(), r.getCreatedAt(), r.getReviewedAt());
        }
    }

    /** One entry of the public list: defanged URL only, no reporter details (FR-032, FR-033, FR-037). */
    public record PublicReportDto(String defangedUrl, ReportCategory category, long reportCount,
            LocalDateTime firstReportedAt, LocalDateTime approvedAt) {}

    /** A report as an administrator reviews it, with the latest verdict for its URL (FR-040). */
    public record AdminReportDto(Long id, String url, String defangedUrl, ReportCategory category, String description,
            ReportStatus status, String reporterName, String reporterEmail, LocalDateTime createdAt,
            LocalDateTime reviewedAt, String reviewedByName, Verdict latestVerdict, LocalDateTime latestCheckedAt) {

        public static AdminReportDto from(ScamReport r, ScanResult latest) {
            return new AdminReportDto(r.getReportId(), r.getNormalizedUrl(), r.getDefangedUrl(), r.getCategory(),
                    r.getDescription(), r.getStatus(), r.getReporter().getName(), r.getReporter().getEmail(),
                    r.getCreatedAt(), r.getReviewedAt(), r.getReviewedBy() == null ? null : r.getReviewedBy().getName(),
                    latest == null ? null : latest.getVerdict(), latest == null ? null : latest.getCheckedAt());
        }
    }
}
