package com.example.registrationlogin.exception;

import com.example.registrationlogin.dto.ApiResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse> handleValidationExceptions(MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();
        for (FieldError error : ex.getBindingResult().getFieldErrors()) {
            errors.put(error.getField(), error.getDefaultMessage());
        }

        String firstErrorMessage = ex.getBindingResult().getAllErrors().isEmpty()
                ? "Validation error"
                : ex.getBindingResult().getAllErrors().get(0).getDefaultMessage();

        ApiResponse response = new ApiResponse(false, firstErrorMessage, errors);
        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiResponse> handleIllegalArgumentException(IllegalArgumentException ex) {
        ApiResponse response = new ApiResponse(false, ex.getMessage());
        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    /**
     * E-mail delivery problems are reported with a fixed, non-sensitive message so that no SMTP
     * server response, account detail or credential reaches the client.
     */
    @ExceptionHandler(EmailDeliveryException.class)
    public ResponseEntity<ApiResponse> handleEmailDeliveryException(EmailDeliveryException ex) {
        ApiResponse response = new ApiResponse(false,
                "We could not send the verification e-mail right now. Please try again later.");
        return new ResponseEntity<>(response, HttpStatus.SERVICE_UNAVAILABLE);
    }

    /**
     * Reports a breached rate limit with HTTP 429 Too Many Requests.
     *
     * <p>The message never contains the identifier that was limited, so the response cannot be
     * used to find out which accounts exist.</p>
     */
    @ExceptionHandler(TooManyRequestsException.class)
    public ResponseEntity<ApiResponse> handleTooManyRequests(TooManyRequestsException ex) {
        ApiResponse response = new ApiResponse(false, ex.getMessage());
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .header("Retry-After", String.valueOf(ex.getRetryAfterSeconds()))
                .body(response);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse> handleGeneralException(Exception ex) {
        // Log the detail server-side, but never echo the exception message to the client:
        // it can contain SQL text, SMTP server responses or other internal detail.
        log.error("Unhandled exception while processing request: {}", ex.getClass().getName(), ex);
        ApiResponse response = new ApiResponse(false, "An unexpected error occurred. Please try again later.");
        return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
