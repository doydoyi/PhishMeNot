package edu.cit.alvarado.phishmenot.verification;

/** VirusTotal engine counts for a URL. */
public record VirusTotalResult(int malicious, int suspicious, int totalEngines) {
}
