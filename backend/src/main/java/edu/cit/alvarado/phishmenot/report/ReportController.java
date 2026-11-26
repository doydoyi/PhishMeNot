package edu.cit.alvarado.phishmenot.report;

import java.util.List;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import edu.cit.alvarado.phishmenot.auth.CurrentUserService;
import edu.cit.alvarado.phishmenot.report.ReportDtos.MyReportDto;
import edu.cit.alvarado.phishmenot.report.ReportDtos.PublicReportDto;
import edu.cit.alvarado.phishmenot.verification.UrlNormalizer;

/** Scam reports: submit and list your own (signed in), and the public list (anyone, GET /api/reports/public). */
@RestController
@RequestMapping("/api/reports")
public class ReportController {

    private final ReportService reportService;
    private final CurrentUserService currentUserService;

    public ReportController(ReportService reportService, CurrentUserService currentUserService) {
        this.reportService = reportService;
        this.currentUserService = currentUserService;
    }

    public record ReportRequest(
            @NotBlank(message = "Please enter the link you want to report")
            @Size(max = UrlNormalizer.MAX_LENGTH, message = "This link is too long (maximum 2048 characters)") String url,
            @NotNull(message = "Please choose a category") ReportCategory category,
            @Size(max = 500, message = "Description must be at most 500 characters") String description) {}

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public MyReportDto submit(@Valid @RequestBody ReportRequest req, Authentication authentication) {
        return reportService.submit(currentUserService.require(authentication), req.url(), req.category(), req.description());
    }

    @GetMapping("/mine")
    public List<MyReportDto> mine(Authentication authentication) {
        return reportService.myReports(currentUserService.require(authentication));
    }

    @GetMapping("/public")
    public List<PublicReportDto> publicList(@RequestParam(defaultValue = "") String query,
            @RequestParam(required = false) ReportCategory category) {
        return reportService.publicReports(query, category);
    }
}
