package edu.cit.alvarado.phishmenot.admin;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import edu.cit.alvarado.phishmenot.common.ApiException;
import edu.cit.alvarado.phishmenot.report.ReportDtos.AdminReportDto;
import edu.cit.alvarado.phishmenot.report.ReportStatus;
import edu.cit.alvarado.phishmenot.report.ScamReport;
import edu.cit.alvarado.phishmenot.report.ScamReportRepository;
import edu.cit.alvarado.phishmenot.user.Role;
import edu.cit.alvarado.phishmenot.user.User;
import edu.cit.alvarado.phishmenot.user.UserDto;
import edu.cit.alvarado.phishmenot.user.UserRepository;
import edu.cit.alvarado.phishmenot.verification.ScanResult;
import edu.cit.alvarado.phishmenot.verification.ScanResultDto;
import edu.cit.alvarado.phishmenot.verification.ScanResultRepository;
import edu.cit.alvarado.phishmenot.verification.Verdict;
import edu.cit.alvarado.phishmenot.verification.VerdictEngine;
import edu.cit.alvarado.phishmenot.verification.VerificationRepository;
import edu.cit.alvarado.phishmenot.verification.VerificationService;

/**
 * Administrator operations. Guarded by both the URL rule in SecurityConfig and method security here,
 * so a mis-mapped endpoint still cannot leak admin data (FR-039, NFR-006).
 */
@Service
@PreAuthorize("hasRole('ADMIN')")
public class AdminService {

    public static final int MAX_PAGE_SIZE = 50;

    public static final int STATS_DAYS = 30;

    private final UserRepository userRepository;
    private final ScamReportRepository reports;
    private final ScanResultRepository scanResults;
    private final VerificationRepository verifications;
    private final VerificationService verificationService;
    private final VerdictEngine engine;

    public AdminService(UserRepository userRepository, ScamReportRepository reports, ScanResultRepository scanResults,
            VerificationRepository verifications, VerificationService verificationService, VerdictEngine engine) {
        this.userRepository = userRepository;
        this.reports = reports;
        this.scanResults = scanResults;
        this.verifications = verifications;
        this.verificationService = verificationService;
        this.engine = engine;
    }

    public enum ReviewAction { APPROVE, REJECT, REMOVE }

    public record DayCount(LocalDate date, long count) {}

    public record StatisticsDto(long totalVerifications, Map<Verdict, Long> verificationsByVerdict,
            Map<ReportStatus, Long> reportsByStatus, List<DayCount> verificationsPerDay) {}

    public record AdminDashboardDto(long totalUsers, long generalUsers, long administrators,
            long newUsersLast7Days, List<UserDto> recentUsers) {}

    public record UserPageDto(List<UserDto> users, int page, int size, long totalElements, int totalPages) {}

    @Transactional(readOnly = true)
    public AdminDashboardDto dashboard() {
        return new AdminDashboardDto(
                userRepository.count(),
                userRepository.countByRole(Role.USER),
                userRepository.countByRole(Role.ADMIN),
                userRepository.countByCreatedAtAfter(LocalDateTime.now().minusDays(7)),
                userRepository.findTop5ByOrderByCreatedAtDesc().stream().map(UserDto::from).toList());
    }

    /** Reports with a given status, oldest first, each with the latest verdict for its URL (FR-040). */
    @Transactional(readOnly = true)
    public List<AdminReportDto> reports(ReportStatus status) {
        return reports.findByStatusWithPeople(status).stream()
                .map(r -> AdminReportDto.from(r, scanResults.findFirstByUrlHashOrderByCheckedAtDesc(r.getUrlHash()).orElse(null)))
                .toList();
    }

    /** Approve or reject a pending report, or remove an approved one from the public list (FR-041, FR-042). */
    @Transactional
    public AdminReportDto review(User admin, Long reportId, ReviewAction action) {
        ScamReport report = findReport(reportId);
        switch (action) {
            case APPROVE -> report.approve(admin);
            case REJECT -> report.reject(admin);
            case REMOVE -> report.remove(admin);
        }
        return AdminReportDto.from(report, scanResults.findFirstByUrlHashOrderByCheckedAtDesc(report.getUrlHash()).orElse(null));
    }

    /** Re-checks a reported URL against both services now, bypassing the 24-hour cache (FR-043). */
    @Transactional
    public ScanResultDto recheck(Long reportId) {
        ScamReport report = findReport(reportId);
        ScanResult fresh = verificationService.scan(report.getNormalizedUrl(), report.getUrlHash());
        report.setScanResult(fresh);
        return ScanResultDto.from(fresh, engine);
    }

    /** Totals, verdict and report-status breakdowns, and verifications per day for the last 30 days (FR-044). */
    @Transactional(readOnly = true)
    public StatisticsDto statistics() {
        Map<Verdict, Long> byVerdict = new EnumMap<>(Verdict.class);
        for (Verdict v : Verdict.values()) byVerdict.put(v, 0L);
        verifications.countByVerdict().forEach(row -> byVerdict.put((Verdict) row[0], (Long) row[1]));

        Map<ReportStatus, Long> byStatus = new EnumMap<>(ReportStatus.class);
        for (ReportStatus s : ReportStatus.values()) byStatus.put(s, 0L);
        reports.countByStatus().forEach(row -> byStatus.put((ReportStatus) row[0], (Long) row[1]));

        LocalDate today = LocalDate.now();
        LocalDate first = today.minusDays(STATS_DAYS - 1);
        // shortcut: counts timestamps in memory, fine for tens of thousands of checks a month; use GROUP BY DATE beyond that
        Map<LocalDate, Long> perDay = new TreeMap<>(verifications.findCreatedAtSince(first.atStartOfDay()).stream()
                .collect(Collectors.groupingBy(LocalDateTime::toLocalDate, Collectors.counting())));
        List<DayCount> days = first.datesUntil(today.plusDays(1))
                .map(d -> new DayCount(d, perDay.getOrDefault(d, 0L))).toList();

        return new StatisticsDto(verifications.count(), byVerdict, byStatus, days);
    }

    private ScamReport findReport(Long reportId) {
        return reports.findById(reportId)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "This report was not found."));
    }

    @Transactional(readOnly = true)
    public UserPageDto listUsers(String query, int page, int size) {
        if (page < 0 || size < 1) {
            throw new IllegalArgumentException("page must be >= 0 and size >= 1");
        }
        PageRequest pageable = PageRequest.of(page, Math.min(size, MAX_PAGE_SIZE), Sort.by(Sort.Direction.DESC, "createdAt"));
        String q = query == null ? "" : query.trim();
        Page<UserDto> result = (q.isEmpty()
                ? userRepository.findAll(pageable)
                : userRepository.findByNameContainingIgnoreCaseOrEmailContainingIgnoreCase(q, q, pageable))
                .map(UserDto::from);
        return new UserPageDto(result.getContent(), result.getNumber(), result.getSize(),
                result.getTotalElements(), result.getTotalPages());
    }
}
