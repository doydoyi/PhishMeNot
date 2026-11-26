package edu.cit.alvarado.phishmenot.verification;

import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;

import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/**
 * SCAN_RESULTS (SRS ERD): the combined outcome of checking one normalized URL against Google Safe
 * Browsing and VirusTotal. Reused for 24 hours (FR-016). Counts are null when VirusTotal could not be
 * reached; gsbThreatTypes is null when Safe Browsing could not be reached (partial check, FR-017).
 */
@Entity
@Table(name = "scan_results", indexes = @Index(name = "idx_scan_results_url_hash", columnList = "url_hash"))
public class ScanResult {

    public static final long FRESH_HOURS = 24;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "scan_result_id")
    private Long scanResultId;

    @Column(name = "normalized_url", nullable = false, length = 2048)
    private String normalizedUrl;

    @Column(name = "url_hash", nullable = false, length = 64)
    private String urlHash;

    @Enumerated(EnumType.STRING)
    @JdbcTypeCode(SqlTypes.VARCHAR)
    @Column(name = "verdict", nullable = false, length = 20)
    private Verdict verdict;

    /** Comma-separated Safe Browsing threat types; empty string = checked, no match; null = not checked. */
    @Column(name = "gsb_threat_types", length = 255)
    private String gsbThreatTypes;

    @Column(name = "vt_malicious_count")
    private Integer vtMaliciousCount;

    @Column(name = "vt_suspicious_count")
    private Integer vtSuspiciousCount;

    @Column(name = "vt_total_engines")
    private Integer vtTotalEngines;

    @Column(name = "is_partial_check", nullable = false)
    private boolean partialCheck;

    @Column(name = "checked_at", nullable = false)
    private LocalDateTime checkedAt;

    protected ScanResult() {
        // for JPA
    }

    public ScanResult(String normalizedUrl, String urlHash, Verdict verdict,
            SafeBrowsingResult safeBrowsing, VirusTotalResult virusTotal) {
        this.normalizedUrl = normalizedUrl;
        this.urlHash = urlHash;
        this.verdict = verdict;
        this.gsbThreatTypes = safeBrowsing == null ? null : String.join(",", safeBrowsing.threatTypes());
        if (virusTotal != null) {
            this.vtMaliciousCount = virusTotal.malicious();
            this.vtSuspiciousCount = virusTotal.suspicious();
            this.vtTotalEngines = virusTotal.totalEngines();
        }
        this.partialCheck = safeBrowsing == null || virusTotal == null;
        this.checkedAt = LocalDateTime.now();
    }

    public boolean isFresh(LocalDateTime now) {
        return checkedAt.isAfter(now.minusHours(FRESH_HOURS));
    }

    public boolean safeBrowsingChecked() { return gsbThreatTypes != null; }
    public boolean virusTotalChecked() { return vtTotalEngines != null; }

    public java.util.List<String> threatTypes() {
        return gsbThreatTypes == null || gsbThreatTypes.isEmpty() ? java.util.List.of() : java.util.List.of(gsbThreatTypes.split(","));
    }

    public Long getScanResultId() { return scanResultId; }
    public String getNormalizedUrl() { return normalizedUrl; }
    public String getUrlHash() { return urlHash; }
    public Verdict getVerdict() { return verdict; }
    public Integer getVtMaliciousCount() { return vtMaliciousCount; }
    public Integer getVtSuspiciousCount() { return vtSuspiciousCount; }
    public Integer getVtTotalEngines() { return vtTotalEngines; }
    public boolean isPartialCheck() { return partialCheck; }
    public LocalDateTime getCheckedAt() { return checkedAt; }
}
