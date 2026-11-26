package edu.cit.alvarado.phishmenot;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.jsonPath;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withResourceNotFound;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

import edu.cit.alvarado.phishmenot.verification.ExternalServiceException;
import edu.cit.alvarado.phishmenot.verification.SafeBrowsingClient;
import edu.cit.alvarado.phishmenot.verification.VirusTotalClient;

/** Checks the exact HTTP requests sent to Google Safe Browsing v4 and VirusTotal v3, and how responses are read. */
class ThreatClientsTest {

    private static final String URL = "https://bpi-secure.example.com/";
    // base64url of URL without padding, as VirusTotal requires
    private static final String VT_ID = "aHR0cHM6Ly9icGktc2VjdXJlLmV4YW1wbGUuY29tLw";

    @Test
    void safeBrowsingSendsAllFourThreatTypesAndReadsMatches() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        SafeBrowsingClient client = new SafeBrowsingClient(builder, "gsb-key", "https://gsb.test/v4");

        server.expect(requestTo("https://gsb.test/v4/threatMatches:find?key=gsb-key"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(jsonPath("$.threatInfo.threatTypes.length()").value(4))
                .andExpect(jsonPath("$.threatInfo.threatEntries[0].url").value(URL))
                .andRespond(withSuccess("""
                        {"matches":[{"threatType":"SOCIAL_ENGINEERING"},{"threatType":"MALWARE"},{"threatType":"MALWARE"}]}""",
                        MediaType.APPLICATION_JSON));
        assertThat(client.check(URL).threatTypes()).containsExactly("MALWARE", "SOCIAL_ENGINEERING");

        server.reset();
        server.expect(requestTo("https://gsb.test/v4/threatMatches:find?key=gsb-key"))
                .andRespond(withSuccess("{}", MediaType.APPLICATION_JSON));
        assertThat(client.check(URL).matched()).isFalse();
        server.verify();
    }

    @Test
    void virusTotalUsesExistingAnalysis() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        VirusTotalClient client = new VirusTotalClient(builder, "vt-key", "https://vt.test/api/v3", 2, Duration.ZERO);

        server.expect(requestTo("https://vt.test/api/v3/urls/" + VT_ID))
                .andExpect(header("x-apikey", "vt-key"))
                .andRespond(withSuccess("""
                        {"data":{"attributes":{"last_analysis_stats":
                          {"malicious":5,"suspicious":1,"harmless":60,"undetected":24,"timeout":0}}}}""",
                        MediaType.APPLICATION_JSON));
        var result = client.check(URL);
        assertThat(result.malicious()).isEqualTo(5);
        assertThat(result.suspicious()).isEqualTo(1);
        assertThat(result.totalEngines()).isEqualTo(90);
        server.verify();
    }

    @Test
    void virusTotalSubmitsUnknownUrlAndPollsAnalysis() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        VirusTotalClient client = new VirusTotalClient(builder, "vt-key", "https://vt.test/api/v3", 2, Duration.ZERO);

        server.expect(requestTo("https://vt.test/api/v3/urls/" + VT_ID)).andRespond(withResourceNotFound());
        server.expect(requestTo("https://vt.test/api/v3/urls"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(content().formDataContains(java.util.Map.of("url", URL)))
                .andRespond(withSuccess("{\"data\":{\"id\":\"an-1\"}}", MediaType.APPLICATION_JSON));
        server.expect(requestTo("https://vt.test/api/v3/analyses/an-1"))
                .andRespond(withSuccess("{\"data\":{\"attributes\":{\"status\":\"queued\",\"stats\":{}}}}", MediaType.APPLICATION_JSON));
        server.expect(requestTo("https://vt.test/api/v3/analyses/an-1"))
                .andRespond(withSuccess("""
                        {"data":{"attributes":{"status":"completed","stats":
                          {"malicious":0,"suspicious":0,"harmless":70,"undetected":20,"timeout":0}}}}""",
                        MediaType.APPLICATION_JSON));
        assertThat(client.check(URL).totalEngines()).isEqualTo(90);
        server.verify();
    }

    @Test
    void failuresAreReportedNotHidden() {
        assertThatThrownBy(() -> new VirusTotalClient(RestClient.builder(), "", "https://vt.test", 1, Duration.ZERO).check(URL))
                .isInstanceOf(ExternalServiceException.class).hasMessageContaining("VIRUSTOTAL_API_KEY");
        assertThatThrownBy(() -> new SafeBrowsingClient(RestClient.builder(), " ", "https://gsb.test").check(URL))
                .isInstanceOf(ExternalServiceException.class).hasMessageContaining("SAFE_BROWSING_API_KEY");

        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        VirusTotalClient client = new VirusTotalClient(builder, "vt-key", "https://vt.test/api/v3", 2, Duration.ZERO);
        server.expect(requestTo("https://vt.test/api/v3/urls/" + VT_ID)).andRespond(withStatus(HttpStatus.TOO_MANY_REQUESTS));
        assertThatThrownBy(() -> client.check(URL)).isInstanceOf(RestClientResponseException.class);
    }
}
