package edu.cit.alvarado.phishmenot.verification;

import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

import edu.cit.alvarado.phishmenot.user.User;

/** VERIFICATIONS (SRS ERD): one link check performed by a user; an entry in their history. */
@Entity
@Table(name = "verifications")
public class Verification {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "verification_id")
    private Long verificationId;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "scan_result_id", nullable = false)
    private ScanResult scanResult;

    @Column(name = "submitted_url", nullable = false, length = 2048)
    private String submittedUrl;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    protected Verification() {
        // for JPA
    }

    public Verification(User user, ScanResult scanResult, String submittedUrl) {
        this.user = user;
        this.scanResult = scanResult;
        this.submittedUrl = submittedUrl;
        this.createdAt = LocalDateTime.now();
    }

    public Long getVerificationId() { return verificationId; }
    public User getUser() { return user; }
    public ScanResult getScanResult() { return scanResult; }
    public String getSubmittedUrl() { return submittedUrl; }
    public LocalDateTime getCreatedAt() { return createdAt; }
}
