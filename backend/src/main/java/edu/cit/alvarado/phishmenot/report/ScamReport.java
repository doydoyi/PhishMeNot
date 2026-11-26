package edu.cit.alvarado.phishmenot.report;

import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import org.springframework.http.HttpStatus;

import edu.cit.alvarado.phishmenot.common.ApiException;
import edu.cit.alvarado.phishmenot.user.User;
import edu.cit.alvarado.phishmenot.verification.ScanResult;

/** SCAM_REPORTS (SRS ERD). One report per user per URL (UK reporter_id + url_hash, FR-035). */
@Entity
@Table(name = "scam_reports", uniqueConstraints =
        @UniqueConstraint(name = "uk_scam_reports_reporter_url", columnNames = {"reporter_id", "url_hash"}))
public class ScamReport {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "report_id")
    private Long reportId;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "reporter_id", nullable = false)
    private User reporter;

    /** The latest scan of this URL when it was reported (evidence); may be null. */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "scan_result_id")
    private ScanResult scanResult;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "reviewed_by")
    private User reviewedBy;

    @Column(name = "normalized_url", nullable = false, length = 2048)
    private String normalizedUrl;

    @Column(name = "url_hash", nullable = false, length = 64)
    private String urlHash;

    @Enumerated(EnumType.STRING)
    @JdbcTypeCode(SqlTypes.VARCHAR)
    @Column(name = "category", nullable = false, length = 30)
    private ReportCategory category;

    @Column(name = "description", length = 500)
    private String description;

    @Enumerated(EnumType.STRING)
    @JdbcTypeCode(SqlTypes.VARCHAR)
    @Column(name = "status", nullable = false, length = 20)
    private ReportStatus status;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "reviewed_at")
    private LocalDateTime reviewedAt;

    protected ScamReport() {
        // for JPA
    }

    public ScamReport(User reporter, ScanResult scanResult, String normalizedUrl, String urlHash,
            ReportCategory category, String description) {
        this.reporter = reporter;
        this.scanResult = scanResult;
        this.normalizedUrl = normalizedUrl;
        this.urlHash = urlHash;
        this.category = category;
        this.description = description;
        this.status = ReportStatus.PENDING; // FR-031
        this.createdAt = LocalDateTime.now();
    }

    public void approve(User admin) {
        transition(ReportStatus.PENDING, ReportStatus.APPROVED, admin);
    }

    public void reject(User admin) {
        transition(ReportStatus.PENDING, ReportStatus.REJECTED, admin);
    }

    /** Takes an approved report off the public list (FR-042). */
    public void remove(User admin) {
        transition(ReportStatus.APPROVED, ReportStatus.REMOVED, admin);
    }

    private void transition(ReportStatus from, ReportStatus to, User admin) {
        if (status != from) {
            throw new ApiException(HttpStatus.CONFLICT, "This report is " + status.name().toLowerCase()
                    + ", so it cannot be " + (to == ReportStatus.REMOVED ? "removed" : to.name().toLowerCase()) + ".");
        }
        this.status = to;
        this.reviewedBy = admin;
        this.reviewedAt = LocalDateTime.now();
    }

    /** Non-clickable form for the public list, e.g. hxxps://example[.]com/login (FR-033). */
    public String getDefangedUrl() {
        return defang(normalizedUrl);
    }

    static String defang(String url) {
        int schemeEnd = url.indexOf("://");
        int authorityEnd = schemeEnd + 3;
        while (authorityEnd < url.length() && "/?#".indexOf(url.charAt(authorityEnd)) < 0) {
            authorityEnd++;
        }
        return url.substring(0, schemeEnd).replace("http", "hxxp") + "://"
                + url.substring(schemeEnd + 3, authorityEnd).replace(".", "[.]") + url.substring(authorityEnd);
    }

    public void setScanResult(ScanResult scanResult) { this.scanResult = scanResult; }

    public Long getReportId() { return reportId; }
    public User getReporter() { return reporter; }
    public ScanResult getScanResult() { return scanResult; }
    public User getReviewedBy() { return reviewedBy; }
    public String getNormalizedUrl() { return normalizedUrl; }
    public String getUrlHash() { return urlHash; }
    public ReportCategory getCategory() { return category; }
    public String getDescription() { return description; }
    public ReportStatus getStatus() { return status; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public LocalDateTime getReviewedAt() { return reviewedAt; }
}
