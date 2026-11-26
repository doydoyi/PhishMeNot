package edu.cit.alvarado.phishmenot.report;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import edu.cit.alvarado.phishmenot.common.ApiException;
import edu.cit.alvarado.phishmenot.report.ReportDtos.MyReportDto;
import edu.cit.alvarado.phishmenot.report.ReportDtos.PublicReportDto;
import edu.cit.alvarado.phishmenot.user.User;
import edu.cit.alvarado.phishmenot.verification.ScanResultRepository;
import edu.cit.alvarado.phishmenot.verification.UrlNormalizer;

/** Scam link reporting and the public list of approved reports (SRS Feature 4). */
@Service
public class ReportService {

    public static final int PUBLIC_LIST_LIMIT = 100;

    private final ScamReportRepository reports;
    private final ScanResultRepository scanResults;
    private final UrlNormalizer normalizer;

    public ReportService(ScamReportRepository reports, ScanResultRepository scanResults, UrlNormalizer normalizer) {
        this.reports = reports;
        this.scanResults = scanResults;
        this.normalizer = normalizer;
    }

    /** Files a PENDING report (FR-029 to FR-031); a user may report the same URL only once (FR-035). */
    @Transactional
    public MyReportDto submit(User reporter, String url, ReportCategory category, String description) {
        String normalized = normalizer.normalize(url);
        String hash = normalizer.hash(normalized);
        if (reports.existsByReporterAndUrlHash(reporter, hash)) {
            throw new ApiException(HttpStatus.CONFLICT, "You have already reported this link. You can follow its status under My reports.");
        }
        String text = description == null || description.isBlank() ? null : description.trim();
        ScamReport report = new ScamReport(reporter, scanResults.findFirstByUrlHashOrderByCheckedAtDesc(hash).orElse(null),
                normalized, hash, category, text);
        try {
            return MyReportDto.from(reports.saveAndFlush(report));
        } catch (DataIntegrityViolationException e) {
            throw new ApiException(HttpStatus.CONFLICT, "You have already reported this link.");
        }
    }

    @Transactional(readOnly = true)
    public List<MyReportDto> myReports(User reporter) {
        return reports.findByReporterOrderByCreatedAtDesc(reporter).stream().map(MyReportDto::from).toList();
    }

    /**
     * Approved reports grouped by URL, newest approval first, with how many users reported each URL
     * (FR-032, FR-033, FR-034, FR-037). Viewable without signing in.
     */
    @Transactional(readOnly = true)
    public List<PublicReportDto> publicReports(String query, ReportCategory category) {
        String q = query == null ? "" : query.trim().toLowerCase();
        // shortcut: groups in memory, fine for thousands of approved reports; move to a GROUP BY query beyond that
        Map<String, List<ScamReport>> byUrl = new LinkedHashMap<>();
        for (ScamReport r : reports.findApproved(category, q)) {
            byUrl.computeIfAbsent(r.getUrlHash(), k -> new ArrayList<>()).add(r);
        }
        return byUrl.values().stream()
                .limit(PUBLIC_LIST_LIMIT)
                .map(group -> {
                    ScamReport latest = group.get(0);
                    return new PublicReportDto(latest.getDefangedUrl(), latest.getCategory(), group.size(),
                            group.stream().map(ScamReport::getCreatedAt).min(Comparator.naturalOrder()).orElseThrow(),
                            latest.getReviewedAt());
                })
                .toList();
    }
}
