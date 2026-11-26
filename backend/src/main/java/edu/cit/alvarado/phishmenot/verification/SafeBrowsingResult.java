package edu.cit.alvarado.phishmenot.verification;

import java.util.List;

/** Google Safe Browsing answer: the threat types the URL matched (empty = no match). */
public record SafeBrowsingResult(List<String> threatTypes) {

    public boolean matched() {
        return !threatTypes.isEmpty();
    }
}
