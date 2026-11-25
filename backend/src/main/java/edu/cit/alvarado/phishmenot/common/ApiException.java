package edu.cit.alvarado.phishmenot.common;

import org.springframework.http.HttpStatus;

/** A request that fails for a reason the user can fix; the message is shown to them as-is. */
public class ApiException extends RuntimeException {

    private final HttpStatus status;

    public ApiException(HttpStatus status, String message) {
        super(message);
        this.status = status;
    }

    public HttpStatus getStatus() {
        return status;
    }
}
