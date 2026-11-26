package edu.cit.alvarado.phishmenot.verification;

/** A threat-checking service could not give an answer (not configured, rate-limited, down, or timed out). */
public class ExternalServiceException extends RuntimeException {

    public ExternalServiceException(String message) {
        super(message);
    }
}
