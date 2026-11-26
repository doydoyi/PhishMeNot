package edu.cit.alvarado.phishmenot.verification;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;
import java.util.regex.Pattern;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import edu.cit.alvarado.phishmenot.common.ApiException;
import edu.cit.alvarado.phishmenot.common.Hashes;

/**
 * Validates and normalizes submitted links (FR-002, FR-003): trims spaces, adds https:// when no scheme
 * is given, lowercases the scheme and domain, and accepts only http/https web addresses.
 * The link is never opened or fetched (NFR-010).
 */
@Component
public class UrlNormalizer {

    public static final int MAX_LENGTH = 2048;
    private static final Pattern HAS_SCHEME = Pattern.compile("^[a-zA-Z][a-zA-Z0-9+.-]*://");

    public String normalize(String input) {
        if (input == null || input.isBlank()) {
            throw invalid("Please enter a link to check.");
        }
        String url = input.trim();
        if (url.chars().anyMatch(Character::isWhitespace)) {
            throw invalid("A link cannot contain spaces. Paste the exact link you received.");
        }
        if (!HAS_SCHEME.matcher(url).find()) {
            url = "https://" + url;
        }
        URI uri;
        try {
            uri = new URI(url);
        } catch (URISyntaxException e) {
            throw invalid("This does not look like a valid web address.");
        }
        String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
        if (!scheme.equals("http") && !scheme.equals("https")) {
            throw invalid("Only web links (http:// or https://) can be checked.");
        }
        String host = uri.getHost();
        if (host == null || !host.contains(".") || host.startsWith(".") || host.endsWith(".")) {
            throw invalid("This does not look like a valid web address.");
        }
        int authorityStart = url.indexOf("://") + 3;
        int authorityEnd = authorityStart;
        while (authorityEnd < url.length() && "/?#".indexOf(url.charAt(authorityEnd)) < 0) {
            authorityEnd++;
        }
        String rest = url.substring(authorityEnd);
        String normalized = scheme + "://" + url.substring(authorityStart, authorityEnd).toLowerCase(Locale.ROOT)
                + (rest.isEmpty() ? "/" : rest);
        if (normalized.length() > MAX_LENGTH) {
            throw invalid("This link is too long (maximum " + MAX_LENGTH + " characters).");
        }
        return normalized;
    }

    public String hash(String normalizedUrl) {
        return Hashes.sha256(normalizedUrl);
    }

    private static ApiException invalid(String message) {
        return new ApiException(HttpStatus.BAD_REQUEST, message);
    }
}
