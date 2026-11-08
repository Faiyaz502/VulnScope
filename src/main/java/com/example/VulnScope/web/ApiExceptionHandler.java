package com.example.VulnScope.web;

import java.time.Instant;

import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.bind.MethodArgumentNotValidException;

@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(MethodArgumentNotValidException.class)
    ProblemDetail handleValidationException(MethodArgumentNotValidException ignored) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, "Request validation failed.");
        problem.setTitle("Invalid request");
        problem.setProperty("timestamp", Instant.now());
        problem.setProperty("errorCode", "VALIDATION_FAILED");
        return problem;
    }

    @ExceptionHandler(ApiException.class)
    ProblemDetail handleApiException(ApiException exception) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(exception.getStatus(), exception.getMessage());
        problem.setTitle("Request rejected");
        problem.setProperty("timestamp", Instant.now());
        problem.setProperty("errorCode", exception.getErrorCode());
        return problem;
    }

    @ExceptionHandler(Exception.class)
    ProblemDetail handleUnexpectedException(Exception ignored) {
        // Never expose exception messages, class names, stack traces, or database details to clients.
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(
            HttpStatus.INTERNAL_SERVER_ERROR,
            "The request could not be completed.");
        problem.setTitle("Internal server error");
        problem.setProperty("timestamp", Instant.now());
        problem.setProperty("errorCode", "INTERNAL_ERROR");
        return problem;
    }
}
