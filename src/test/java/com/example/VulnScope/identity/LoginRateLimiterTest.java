package com.example.VulnScope.identity;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class LoginRateLimiterTest {
    @Test
    void blocksAfterFiveFailuresAndResetsAfterSuccessfulLogin() {
        LoginRateLimiter limiter = new LoginRateLimiter();
        for (int i = 0; i < 5; i++) {
            assertTrue(limiter.allow("127.0.0.1"));
            limiter.recordFailure("127.0.0.1");
        }
        assertFalse(limiter.allow("127.0.0.1"));
        limiter.clear("127.0.0.1");
        assertTrue(limiter.allow("127.0.0.1"));
    }
}
