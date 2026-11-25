package edu.cit.alvarado.phishmenot.common;

import java.time.Instant;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonInclude;

/** Uniform JSON error body returned by the API. {@code fieldErrors} maps a request field to its message. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApiError(int status, String error, String message, String path, Instant timestamp,
        Map<String, String> fieldErrors) {

    public static ApiError of(int status, String error, String message, String path) {
        return new ApiError(status, error, message, path, Instant.now(), null);
    }
}
