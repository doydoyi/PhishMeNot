package edu.cit.alvarado.phishmenot.verification;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;

import com.fasterxml.jackson.databind.JsonNode;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

/**
 * VirusTotal API v3 (FR-012): reads the existing analysis of a URL, or submits it for scanning and
 * waits briefly for the result. The free API allows 4 requests per minute, so polling is limited.
 */
@Component
public class VirusTotalClient {

    private final RestClient rest;
    private final String apiKey;
    private final int pollAttempts;
    private final Duration pollDelay;

    public VirusTotalClient(RestClient.Builder builder,
            @Value("${app.virustotal.api-key:}") String apiKey,
            @Value("${app.virustotal.base-url:https://www.virustotal.com/api/v3}") String baseUrl,
            @Value("${app.virustotal.poll-attempts:2}") int pollAttempts,
            @Value("${app.virustotal.poll-delay:10s}") Duration pollDelay) {
        this.rest = builder.clone().baseUrl(baseUrl).defaultHeader("x-apikey", apiKey == null ? "" : apiKey).build();
        this.apiKey = apiKey;
        this.pollAttempts = pollAttempts;
        this.pollDelay = pollDelay;
    }

    public VirusTotalResult check(String url) {
        if (apiKey == null || apiKey.isBlank()) {
            throw new ExternalServiceException("VirusTotal API key is not configured (VIRUSTOTAL_API_KEY)");
        }
        String urlId = Base64.getUrlEncoder().withoutPadding().encodeToString(url.getBytes(StandardCharsets.UTF_8));
        try {
            JsonNode report = rest.get().uri("/urls/{id}", urlId).retrieve().body(JsonNode.class);
            JsonNode stats = report.path("data").path("attributes").path("last_analysis_stats");
            if (!stats.isMissingNode() && totalOf(stats) > 0) {
                return toResult(stats);
            }
        } catch (HttpClientErrorException.NotFound e) {
            // never analysed before: submit it below
        }
        var form = new LinkedMultiValueMap<String, String>();
        form.add("url", url);
        JsonNode submitted = rest.post().uri("/urls").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form).retrieve().body(JsonNode.class);
        String analysisId = submitted.path("data").path("id").asText();
        for (int attempt = 0; attempt < pollAttempts; attempt++) {
            sleep(pollDelay);
            JsonNode analysis = rest.get().uri("/analyses/{id}", analysisId).retrieve().body(JsonNode.class);
            JsonNode attributes = analysis.path("data").path("attributes");
            if ("completed".equals(attributes.path("status").asText())) {
                return toResult(attributes.path("stats"));
            }
        }
        throw new ExternalServiceException("VirusTotal analysis did not finish in time");
    }

    private static VirusTotalResult toResult(JsonNode stats) {
        return new VirusTotalResult(stats.path("malicious").asInt(), stats.path("suspicious").asInt(), totalOf(stats));
    }

    private static int totalOf(JsonNode stats) {
        return stats.path("malicious").asInt() + stats.path("suspicious").asInt()
                + stats.path("harmless").asInt() + stats.path("undetected").asInt() + stats.path("timeout").asInt();
    }

    private static void sleep(Duration delay) {
        try {
            Thread.sleep(delay);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ExternalServiceException("Interrupted while waiting for VirusTotal");
        }
    }
}
