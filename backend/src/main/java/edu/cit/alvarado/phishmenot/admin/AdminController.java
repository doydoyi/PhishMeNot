package edu.cit.alvarado.phishmenot.admin;

import java.util.List;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import edu.cit.alvarado.phishmenot.auth.CurrentUserService;
import edu.cit.alvarado.phishmenot.report.ReportDtos.AdminReportDto;
import edu.cit.alvarado.phishmenot.report.ReportStatus;
import edu.cit.alvarado.phishmenot.verification.ScanResultDto;

/** Administrator endpoints. Only users with the ADMIN role reach these; others receive 403. */
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final AdminService adminService;
    private final CurrentUserService currentUserService;

    public AdminController(AdminService adminService, CurrentUserService currentUserService) {
        this.adminService = adminService;
        this.currentUserService = currentUserService;
    }

    public record ReviewRequest(@NotNull(message = "Choose APPROVE, REJECT or REMOVE") AdminService.ReviewAction action) {}

    @GetMapping("/reports")
    public List<AdminReportDto> reports(@RequestParam(defaultValue = "PENDING") ReportStatus status) {
        return adminService.reports(status);
    }

    @PatchMapping("/reports/{id}")
    public AdminReportDto review(@PathVariable Long id, @Valid @RequestBody ReviewRequest req, Authentication authentication) {
        return adminService.review(currentUserService.require(authentication), id, req.action());
    }

    @PostMapping("/reports/{id}/recheck")
    public ScanResultDto recheck(@PathVariable Long id) {
        return adminService.recheck(id);
    }

    @GetMapping("/statistics")
    public AdminService.StatisticsDto statistics() {
        return adminService.statistics();
    }

    @GetMapping("/dashboard")
    public AdminService.AdminDashboardDto dashboard() {
        return adminService.dashboard();
    }

    @GetMapping("/users")
    public AdminService.UserPageDto users(@RequestParam(defaultValue = "") String query,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        return adminService.listUsers(query, page, size);
    }
}
