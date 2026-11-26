package edu.cit.alvarado.phishmenot;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oidcLogin;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import edu.cit.alvarado.phishmenot.auth.GoogleProfile;
import edu.cit.alvarado.phishmenot.auth.PasswordResetTokenRepository;
import edu.cit.alvarado.phishmenot.auth.UserAccountService;
import edu.cit.alvarado.phishmenot.report.ScamReportRepository;
import edu.cit.alvarado.phishmenot.user.UserRepository;
import edu.cit.alvarado.phishmenot.verification.ExternalServiceException;
import edu.cit.alvarado.phishmenot.verification.SafeBrowsingClient;
import edu.cit.alvarado.phishmenot.verification.SafeBrowsingResult;
import edu.cit.alvarado.phishmenot.verification.ScanResultRepository;
import edu.cit.alvarado.phishmenot.verification.VerificationRepository;
import edu.cit.alvarado.phishmenot.verification.VirusTotalClient;
import edu.cit.alvarado.phishmenot.verification.VirusTotalResult;

/**
 * Increment 3 workflows end to end through the REST API: verify, cache, partial checks, rate limit,
 * history, reporting, the public list, and admin review, re-check and statistics. The two external
 * services are replaced by test doubles here; their HTTP contracts are covered in ThreatClientsTest.
 */
@SpringBootTest(properties = "app.verification.hourly-limit=5")
@AutoConfigureMockMvc
class LinkCheckingAndReportingTest {

    @Autowired MockMvc mvc;
    @Autowired UserAccountService accounts;
    @Autowired UserRepository users;
    @Autowired PasswordResetTokenRepository tokens;
    @Autowired VerificationRepository verifications;
    @Autowired ScanResultRepository scanResults;
    @Autowired ScamReportRepository reports;
    @MockitoBean SafeBrowsingClient safeBrowsing;
    @MockitoBean VirusTotalClient virusTotal;

    @AfterEach
    void clean() {
        reports.deleteAll();
        verifications.deleteAll();
        scanResults.deleteAll();
        tokens.deleteAll();
        users.deleteAll();
    }

    @BeforeEach
    void accounts() {
        clean();
        accounts.registerOrLogin(new GoogleProfile("g-ana", "ana@example.com", true, "Ana Reyes", null));
        accounts.registerOrLogin(new GoogleProfile("g-ben", "ben@example.com", true, "Ben Cruz", null));
        accounts.registerOrLogin(new GoogleProfile("g-boss", "boss@example.com", true, "Admin Boss", null));
        when(safeBrowsing.check(anyString())).thenReturn(new SafeBrowsingResult(List.of()));
        when(virusTotal.check(anyString())).thenReturn(new VirusTotalResult(0, 0, 90));
    }

    private static RequestPostProcessor as(String sub, String role) {
        return oidcLogin().idToken(t -> t.subject(sub)).authorities(new SimpleGrantedAuthority("ROLE_" + role));
    }

    private static final RequestPostProcessor ANA = as("g-ana", "USER");
    private static final RequestPostProcessor BEN = as("g-ben", "USER");
    private static final RequestPostProcessor ADMIN = as("g-boss", "ADMIN");

    private ResultActions send(MockHttpServletRequestBuilder req, RequestPostProcessor who, String json) throws Exception {
        if (who != null) req = req.with(who);
        return mvc.perform(req.with(csrf()).contentType(MediaType.APPLICATION_JSON).content(json == null ? "" : json));
    }

    private ResultActions verifyUrl(RequestPostProcessor who, String url) throws Exception {
        return send(post("/api/verifications"), who, "{\"url\":\"" + url + "\"}");
    }

    @Test
    void verifiesLinkWithVerdictExplanationAndTips() throws Exception {
        when(safeBrowsing.check("https://gcash-promo.example.com/claim")).thenReturn(new SafeBrowsingResult(List.of("SOCIAL_ENGINEERING")));
        when(virusTotal.check("https://gcash-promo.example.com/claim")).thenReturn(new VirusTotalResult(5, 1, 90));

        verifyUrl(ANA, "  GCASH-promo.example.com/claim ")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.normalizedUrl").value("https://gcash-promo.example.com/claim"))
                .andExpect(jsonPath("$.verdict").value("MALICIOUS"))
                .andExpect(jsonPath("$.explanation").value(org.hamcrest.Matchers.containsString("5 of 90 security engines")))
                .andExpect(jsonPath("$.safetyTips.length()").value(4))
                .andExpect(jsonPath("$.partialCheck").value(false))
                .andExpect(jsonPath("$.cached").value(false));
        assertThat(verifications.count()).isEqualTo(1);
        assertThat(scanResults.findAll().get(0).getVerdict().name()).isEqualTo("MALICIOUS");
    }

    @Test
    void validatesInputAndRequiresSignIn() throws Exception {
        verifyUrl(ANA, "").andExpect(status().isBadRequest());
        verifyUrl(ANA, "not a link").andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.containsString("spaces")));
        verifyUrl(ANA, "ftp://files.example.com").andExpect(status().isBadRequest());
        verifyUrl(null, "https://example.com").andExpect(status().isUnauthorized());
        assertThat(verifications.count()).isZero();
    }

    @Test
    void reusesResultFromLast24HoursWithoutCallingServicesAgain() throws Exception {
        verifyUrl(ANA, "https://shopee-sale.example.com/").andExpect(jsonPath("$.cached").value(false));
        verifyUrl(BEN, "shopee-sale.example.com").andExpect(jsonPath("$.cached").value(true)).andExpect(jsonPath("$.verdict").value("SAFE"));
        verify(virusTotal, times(1)).check("https://shopee-sale.example.com/");
        assertThat(scanResults.count()).isEqualTo(1);
        assertThat(verifications.count()).isEqualTo(2);
    }

    @Test
    void oneServiceDownGivesPartialVerdictBothDownGivesError() throws Exception {
        when(virusTotal.check("https://half.example.com/")).thenThrow(new ExternalServiceException("rate limited"));
        verifyUrl(ANA, "https://half.example.com/")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.partialCheck").value(true))
                .andExpect(jsonPath("$.explanation").value(org.hamcrest.Matchers.containsString("partial check")));

        when(virusTotal.check("https://down.example.com/")).thenThrow(new ExternalServiceException("down"));
        when(safeBrowsing.check("https://down.example.com/")).thenThrow(new RuntimeException("timeout"));
        verifyUrl(ANA, "https://down.example.com/")
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.containsString("try again")));

        // partial results are not cached: the next check calls the services again
        verifyUrl(ANA, "https://half.example.com/").andExpect(jsonPath("$.cached").value(false));
    }

    @Test
    void enforcesHourlyLimit() throws Exception {
        for (int i = 0; i < 5; i++) {
            verifyUrl(ANA, "https://site" + i + ".example.com/").andExpect(status().isOk());
        }
        verifyUrl(ANA, "https://one-more.example.com/").andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.containsString("limit")));
        verifyUrl(BEN, "https://one-more.example.com/").andExpect(status().isOk()); // the limit is per user
    }

    @Test
    void historyIsPrivateFilterableAndDeletable() throws Exception {
        when(virusTotal.check("https://bad.example.com/")).thenReturn(new VirusTotalResult(3, 0, 90));
        verifyUrl(ANA, "https://good.example.com/");
        verifyUrl(ANA, "https://bad.example.com/");
        verifyUrl(BEN, "https://bens-link.example.com/");

        mvc.perform(get("/api/verifications").with(ANA))
                .andExpect(jsonPath("$.totalElements").value(2))
                .andExpect(jsonPath("$.items[0].normalizedUrl").value("https://bad.example.com/")); // newest first
        mvc.perform(get("/api/verifications").param("verdict", "MALICIOUS").with(ANA))
                .andExpect(jsonPath("$.totalElements").value(1));
        mvc.perform(get("/api/verifications").param("query", "GOOD").with(ANA))
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.items[0].verdict").value("SAFE"));

        Long bensEntry = verifications.findAll().stream()
                .filter(v -> v.getSubmittedUrl().contains("bens")).findFirst().orElseThrow().getVerificationId();
        send(delete("/api/verifications/" + bensEntry), ANA, null).andExpect(status().isNotFound());
        send(delete("/api/verifications/" + bensEntry), BEN, null).andExpect(status().isNoContent());
        assertThat(verifications.count()).isEqualTo(2);
    }

    private String report(RequestPostProcessor who, String url, String category) throws Exception {
        return send(post("/api/reports"), who,
                "{\"url\":\"" + url + "\",\"category\":\"" + category + "\",\"description\":\"Got this by SMS\"}")
                .andReturn().getResponse().getContentAsString();
    }

    private Long reportIdFor(String url) {
        return reports.findAll().stream().filter(r -> r.getNormalizedUrl().equals(url)).findFirst().orElseThrow().getReportId();
    }

    @Test
    void reportingIsPendingOncePerUserAndValidated() throws Exception {
        verifyUrl(ANA, "https://bdo-verify.example.com/login");
        send(post("/api/reports"), ANA, """
                {"url":"bdo-verify.example.com/login","category":"FAKE_BANK","description":"Text message asking for OTP"}""")
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.status").value("PENDING"))
                .andExpect(jsonPath("$.url").value("https://bdo-verify.example.com/login"));
        assertThat(reports.findAll().get(0).getScanResult()).isNotNull(); // linked to the verification's result

        send(post("/api/reports"), ANA, """
                {"url":"https://BDO-verify.example.com/login","category":"OTHER"}""").andExpect(status().isConflict());
        send(post("/api/reports"), ANA, "{\"url\":\"https://x.example.com/\"}")
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.fieldErrors.category").exists());
        send(post("/api/reports"), ANA, "{\"url\":\"https://x.example.com/\",\"category\":\"OTHER\",\"description\":\""
                + "a".repeat(501) + "\"}").andExpect(jsonPath("$.fieldErrors.description").exists());
        send(post("/api/reports"), null, "{\"url\":\"https://x.example.com/\",\"category\":\"OTHER\"}")
                .andExpect(status().isUnauthorized());

        mvc.perform(get("/api/reports/mine").with(ANA)).andExpect(jsonPath("$.length()").value(1));
        mvc.perform(get("/api/reports/mine").with(BEN)).andExpect(jsonPath("$.length()").value(0));
    }

    @Test
    void adminReviewControlsThePublicList() throws Exception {
        report(ANA, "https://lbc-parcel.example.com/pay", "FAKE_DELIVERY");
        report(BEN, "https://lbc-parcel.example.com/pay", "FAKE_DELIVERY");
        report(BEN, "https://not-a-scam.example.com/", "OTHER");
        Long anaId = users.findByEmailIgnoreCase("ana@example.com").orElseThrow().getUserId();
        Long anas = reports.findAll().stream().filter(r -> r.getReporter().getUserId().equals(anaId)).findFirst().orElseThrow().getReportId();
        Long bensSame = reports.findAll().stream().filter(r -> !r.getReporter().getUserId().equals(anaId)
                && r.getNormalizedUrl().contains("lbc")).findFirst().orElseThrow().getReportId();
        Long notScam = reportIdFor("https://not-a-scam.example.com/");

        // nothing is public before review, and general users cannot review
        mvc.perform(get("/api/reports/public")).andExpect(jsonPath("$.length()").value(0));
        send(patch("/api/admin/reports/" + anas), ANA, "{\"action\":\"APPROVE\"}").andExpect(status().isForbidden());
        mvc.perform(get("/api/admin/reports").with(BEN)).andExpect(status().isForbidden());

        mvc.perform(get("/api/admin/reports").param("status", "PENDING").with(ADMIN))
                .andExpect(jsonPath("$.length()").value(3))
                .andExpect(jsonPath("$[0].reporterName").value("Ana Reyes"))
                .andExpect(jsonPath("$[0].category").value("FAKE_DELIVERY"))
                .andExpect(jsonPath("$[0].description").value("Got this by SMS"));

        send(patch("/api/admin/reports/" + anas), ADMIN, "{\"action\":\"APPROVE\"}")
                .andExpect(status().isOk()).andExpect(jsonPath("$.status").value("APPROVED"))
                .andExpect(jsonPath("$.reviewedByName").value("Admin Boss"));
        send(patch("/api/admin/reports/" + bensSame), ADMIN, "{\"action\":\"APPROVE\"}").andExpect(status().isOk());
        send(patch("/api/admin/reports/" + notScam), ADMIN, "{\"action\":\"REJECT\"}")
                .andExpect(jsonPath("$.status").value("REJECTED"));
        send(patch("/api/admin/reports/" + notScam), ADMIN, "{\"action\":\"APPROVE\"}").andExpect(status().isConflict());

        // guests see approved reports only, defanged, grouped with the number of reporters
        mvc.perform(get("/api/reports/public"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].defangedUrl").value("hxxps://lbc-parcel[.]example[.]com/pay"))
                .andExpect(jsonPath("$[0].reportCount").value(2))
                .andExpect(jsonPath("$[0].reporterName").doesNotExist());
        mvc.perform(get("/api/reports/public").param("category", "FAKE_BANK")).andExpect(jsonPath("$.length()").value(0));
        mvc.perform(get("/api/reports/public").param("query", "LBC")).andExpect(jsonPath("$.length()").value(1));

        // reporters see their report's status
        mvc.perform(get("/api/reports/mine").with(BEN))
                .andExpect(jsonPath("$[?(@.url == 'https://not-a-scam.example.com/')].status").value("REJECTED"));

        // removing approved reports takes the URL off the public list
        send(patch("/api/admin/reports/" + anas), ADMIN, "{\"action\":\"REMOVE\"}").andExpect(jsonPath("$.status").value("REMOVED"));
        send(patch("/api/admin/reports/" + bensSame), ADMIN, "{\"action\":\"REMOVE\"}").andExpect(status().isOk());
        mvc.perform(get("/api/reports/public")).andExpect(jsonPath("$.length()").value(0));
        send(patch("/api/admin/reports/999999"), ADMIN, "{\"action\":\"APPROVE\"}").andExpect(status().isNotFound());
    }

    @Test
    void adminRecheckBypassesCacheAndUpdatesLatestVerdict() throws Exception {
        verifyUrl(ANA, "https://maya-kyc.example.com/");
        report(ANA, "https://maya-kyc.example.com/", "FAKE_EWALLET");
        Long id = reportIdFor("https://maya-kyc.example.com/");

        when(safeBrowsing.check("https://maya-kyc.example.com/")).thenReturn(new SafeBrowsingResult(List.of("SOCIAL_ENGINEERING")));
        send(post("/api/admin/reports/" + id + "/recheck"), ADMIN, null)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.verdict").value("MALICIOUS"));
        verify(safeBrowsing, times(2)).check("https://maya-kyc.example.com/");
        mvc.perform(get("/api/admin/reports").with(ADMIN)).andExpect(jsonPath("$[0].latestVerdict").value("MALICIOUS"));
        send(post("/api/admin/reports/" + id + "/recheck"), BEN, null).andExpect(status().isForbidden());
    }

    @Test
    void statisticsCountVerdictsReportsAndDays() throws Exception {
        when(virusTotal.check("https://m.example.com/")).thenReturn(new VirusTotalResult(4, 0, 90));
        when(virusTotal.check("https://s.example.com/")).thenReturn(new VirusTotalResult(1, 0, 90));
        verifyUrl(ANA, "https://m.example.com/");
        verifyUrl(ANA, "https://s.example.com/");
        verifyUrl(BEN, "https://ok.example.com/");
        report(ANA, "https://m.example.com/", "OTHER");

        mvc.perform(get("/api/admin/statistics").with(ADMIN))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalVerifications").value(3))
                .andExpect(jsonPath("$.verificationsByVerdict.MALICIOUS").value(1))
                .andExpect(jsonPath("$.verificationsByVerdict.SUSPICIOUS").value(1))
                .andExpect(jsonPath("$.verificationsByVerdict.SAFE").value(1))
                .andExpect(jsonPath("$.reportsByStatus.PENDING").value(1))
                .andExpect(jsonPath("$.verificationsPerDay.length()").value(30))
                .andExpect(jsonPath("$.verificationsPerDay[29].count").value(3));
        mvc.perform(get("/api/admin/statistics").with(ANA)).andExpect(status().isForbidden());
    }
}
