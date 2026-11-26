package edu.cit.alvarado.phishmenot;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;

import org.junit.jupiter.api.Test;

import edu.cit.alvarado.phishmenot.common.ApiException;
import edu.cit.alvarado.phishmenot.verification.SafeBrowsingResult;
import edu.cit.alvarado.phishmenot.verification.ScanResult;
import edu.cit.alvarado.phishmenot.verification.UrlNormalizer;
import edu.cit.alvarado.phishmenot.verification.Verdict;
import edu.cit.alvarado.phishmenot.verification.VerdictEngine;
import edu.cit.alvarado.phishmenot.verification.VirusTotalResult;

/** FR-002/FR-003 (validation, normalization) and FR-013 to FR-015 (verdict rules), without Spring. */
class UrlAndVerdictRulesTest {

    private final UrlNormalizer normalizer = new UrlNormalizer();
    private final VerdictEngine engine = new VerdictEngine();

    @Test
    void normalizesSchemeCaseAndSpaces() {
        assertThat(normalizer.normalize("  GCash-Verify.COM/Login?Ref=ABC  ")).isEqualTo("https://gcash-verify.com/Login?Ref=ABC");
        assertThat(normalizer.normalize("HTTP://Example.COM")).isEqualTo("http://example.com/");
        assertThat(normalizer.normalize("https://bdo.com.ph.secure-login.xyz/#x")).isEqualTo("https://bdo.com.ph.secure-login.xyz/#x");
        assertThat(normalizer.hash("https://example.com/")).hasSize(64);
    }

    @Test
    void rejectsInvalidInput() {
        for (String bad : List.of("", "   ", "not a link", "ftp://example.com/file", "javascript:alert(1)",
                "https://localhost/", "https://exa mple.com", "https://" + "a".repeat(2050) + ".com")) {
            assertThatThrownBy(() -> normalizer.normalize(bad)).as(bad).isInstanceOf(ApiException.class);
        }
    }

    @Test
    void verdictRulesFollowTheSrs() {
        SafeBrowsingResult clean = new SafeBrowsingResult(List.of());
        SafeBrowsingResult phishing = new SafeBrowsingResult(List.of("SOCIAL_ENGINEERING"));
        // FR-013: any Safe Browsing match, or 2+ malicious engines
        assertThat(engine.decide(phishing, new VirusTotalResult(0, 0, 90))).isEqualTo(Verdict.MALICIOUS);
        assertThat(engine.decide(clean, new VirusTotalResult(2, 0, 90))).isEqualTo(Verdict.MALICIOUS);
        // FR-014: exactly one malicious engine, or any suspicious engine, and no Safe Browsing match
        assertThat(engine.decide(clean, new VirusTotalResult(1, 0, 90))).isEqualTo(Verdict.SUSPICIOUS);
        assertThat(engine.decide(clean, new VirusTotalResult(0, 3, 90))).isEqualTo(Verdict.SUSPICIOUS);
        // FR-015: neither reports a threat
        assertThat(engine.decide(clean, new VirusTotalResult(0, 0, 90))).isEqualTo(Verdict.SAFE);
        // FR-017: one service missing still gives a verdict
        assertThat(engine.decide(null, new VirusTotalResult(1, 0, 90))).isEqualTo(Verdict.SUSPICIOUS);
        assertThat(engine.decide(phishing, null)).isEqualTo(Verdict.MALICIOUS);
        assertThatThrownBy(() -> engine.decide(null, null)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void explanationAndTipsArePlainLanguage() {
        ScanResult malicious = new ScanResult("https://x.example.com/", "h", Verdict.MALICIOUS,
                new SafeBrowsingResult(List.of("SOCIAL_ENGINEERING")), new VirusTotalResult(5, 1, 90));
        assertThat(engine.explain(malicious))
                .contains("5 of 90 security engines flagged this link as malicious")
                .contains("phishing (social engineering)");
        assertThat(engine.safetyTips(Verdict.MALICIOUS)).anyMatch(t -> t.contains("OTP"));
        assertThat(engine.safetyTips(Verdict.SAFE)).isEmpty();

        ScanResult partial = new ScanResult("https://x.example.com/", "h", Verdict.SAFE, null, new VirusTotalResult(0, 0, 90));
        assertThat(partial.isPartialCheck()).isTrue();
        assertThat(engine.explain(partial)).contains("partial check").contains("not that the site is guaranteed");
    }
}
