package com.example.VulnScope.identity;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

@Component
public class LoginRateLimiter {
    private static final int MAX_FAILURES = 5;
    private static final Duration WINDOW = Duration.ofMinutes(15);
    private final Map<String, ArrayDeque<Instant>> failures = new ConcurrentHashMap<>();

    public boolean allow(String key) {
        ArrayDeque<Instant> attempts = failures.get(key);
        if (attempts == null) return true;
        synchronized (attempts) { purge(attempts); return attempts.size() < MAX_FAILURES; }
    }
    public void recordFailure(String key) {
        ArrayDeque<Instant> attempts = failures.computeIfAbsent(key, ignored -> new ArrayDeque<>());
        synchronized (attempts) { purge(attempts); attempts.addLast(Instant.now()); }
    }
    public void clear(String key) { failures.remove(key); }
    private void purge(ArrayDeque<Instant> attempts) { Instant cutoff = Instant.now().minus(WINDOW); while (!attempts.isEmpty() && attempts.peekFirst().isBefore(cutoff)) attempts.removeFirst(); }
}
