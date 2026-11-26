package edu.cit.alvarado.phishmenot.verification;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Component;

/** Combines both services into one verdict (FR-013 to FR-015) and explains it in plain language (FR-005, FR-006). */
@Component
public class VerdictEngine {

    private static final Map<String, String> THREAT_NAMES = Map.of(
            "MALWARE", "malware",
            "SOCIAL_ENGINEERING", "phishing (social engineering)",
            "UNWANTED_SOFTWARE", "unwanted software",
            "POTENTIALLY_HARMFUL_APPLICATION", "a potentially harmful app");

    public Verdict decide(SafeBrowsingResult gsb, VirusTotalResult vt) {
        if (gsb == null && vt == null) {
            throw new IllegalArgumentException("At least one service result is required");
        }
        if ((gsb != null && gsb.matched()) || (vt != null && vt.malicious() >= 2)) {
            return Verdict.MALICIOUS;
        }
        if (vt != null && (vt.malicious() == 1 || vt.suspicious() >= 1)) {
            return Verdict.SUSPICIOUS;
        }
        return Verdict.SAFE;
    }

    public String explain(ScanResult r) {
        List<String> parts = new ArrayList<>();
        if (r.virusTotalChecked()) {
            int malicious = r.getVtMaliciousCount();
            int suspicious = r.getVtSuspiciousCount();
            int total = r.getVtTotalEngines();
            if (malicious == 0 && suspicious == 0) {
                parts.add("None of the " + total + " VirusTotal security engines flagged this link.");
            } else {
                List<String> flags = new ArrayList<>();
                if (malicious > 0) flags.add(malicious + " of " + total + " security engines flagged this link as malicious");
                if (suspicious > 0) flags.add(suspicious + (suspicious == 1 ? " engine" : " engines") + " flagged it as suspicious");
                parts.add(capitalize(String.join(", and ", flags)) + ".");
            }
        }
        if (r.safeBrowsingChecked()) {
            List<String> threats = r.threatTypes();
            parts.add(threats.isEmpty()
                    ? "Google Safe Browsing has no record of this link being dangerous."
                    : "Google Safe Browsing lists this link as " + String.join(" and ",
                            threats.stream().map(t -> THREAT_NAMES.getOrDefault(t, t.toLowerCase())).toList()) + ".");
        }
        if (r.isPartialCheck()) {
            parts.add("Only " + (r.virusTotalChecked() ? "VirusTotal" : "Google Safe Browsing")
                    + " could be reached, so this is a partial check.");
        }
        if (r.getVerdict() == Verdict.SAFE) {
            parts.add("\"Safe\" means no known threats were found, not that the site is guaranteed to be safe.");
        }
        return String.join(" ", parts);
    }

    public List<String> safetyTips(Verdict verdict) {
        if (verdict == Verdict.SAFE) {
            return List.of();
        }
        return List.of(
                "Do not enter passwords, OTPs or PINs on this website.",
                "Do not download files or install apps from this link.",
                "If the message claims to be from your bank, e-wallet or a government agency, contact them through their official app or hotline instead.",
                "Warn others by reporting this link.");
    }

    private static String capitalize(String s) {
        return s.isEmpty() ? s : Character.toUpperCase(s.charAt(0)) + s.substring(1);
    }
}
