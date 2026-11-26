package edu.cit.alvarado.phishmenot.verification;

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/** Google Safe Browsing Lookup API v4 (FR-011). The API key stays on the backend (FR-019). */
@Component
public class SafeBrowsingClient {

    static final List<String> THREAT_TYPES = List.of(
            "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION");

    private final RestClient rest;
    private final String apiKey;

    public SafeBrowsingClient(RestClient.Builder builder,
            @Value("${app.safe-browsing.api-key:}") String apiKey,
            @Value("${app.safe-browsing.base-url:https://safebrowsing.googleapis.com/v4}") String baseUrl) {
        this.rest = builder.clone().baseUrl(baseUrl).build();
        this.apiKey = apiKey;
    }

    public SafeBrowsingResult check(String url) {
        if (apiKey == null || apiKey.isBlank()) {
            throw new ExternalServiceException("Google Safe Browsing API key is not configured (SAFE_BROWSING_API_KEY)");
        }
        Map<String, Object> body = Map.of(
                "client", Map.of("clientId", "phishmenot", "clientVersion", "1.0"),
                "threatInfo", Map.of(
                        "threatTypes", THREAT_TYPES,
                        "platformTypes", List.of("ANY_PLATFORM"),
                        "threatEntryTypes", List.of("URL"),
                        "threatEntries", List.of(Map.of("url", url))));
        JsonNode response = rest.post()
                .uri(uri -> uri.path("/threatMatches:find").queryParam("key", apiKey).build())
                .contentType(MediaType.APPLICATION_JSON)
                .body(body)
                .retrieve()
                .body(JsonNode.class);
        List<String> threats = response == null ? List.of()
                : response.path("matches").findValuesAsText("threatType").stream().distinct().sorted().toList();
        return new SafeBrowsingResult(threats);
    }
}
