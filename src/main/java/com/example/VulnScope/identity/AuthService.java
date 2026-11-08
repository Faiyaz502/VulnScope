package com.example.VulnScope.identity;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Locale;
import java.util.UUID;
import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.example.VulnScope.web.ApiException;

@Service
public class AuthService {
    private static final Duration SESSION_TTL = Duration.ofHours(8);
    private static final SecureRandom RANDOM = new SecureRandom();
    private final UserAccountRepository users;
    private final OrganizationRepository organizations;
    private final MembershipRepository memberships;
    private final AuthSessionRepository sessions;
    private final AuditEventRepository auditEvents;
    private final PasswordEncoder passwordEncoder;
    private final LoginRateLimiter rateLimiter;

    public AuthService(UserAccountRepository users, OrganizationRepository organizations, MembershipRepository memberships,
                       AuthSessionRepository sessions, AuditEventRepository auditEvents, PasswordEncoder passwordEncoder,
                       LoginRateLimiter rateLimiter) {
        this.users=users; this.organizations=organizations; this.memberships=memberships; this.sessions=sessions;
        this.auditEvents=auditEvents; this.passwordEncoder=passwordEncoder; this.rateLimiter=rateLimiter;
    }

    @Transactional
    public SessionResult register(AuthDtos.RegisterRequest request, String ipAddress) {
        String email = normalizeEmail(request.email());
        if (users.existsByEmail(email)) throw new ApiException(HttpStatus.CONFLICT, "EMAIL_ALREADY_REGISTERED", "Unable to create account with these details.");
        UserAccount user = users.save(new UserAccount(UUID.randomUUID(), email, passwordEncoder.encode(request.password()), request.displayName().trim()));
        Organization organization = organizations.save(new Organization(UUID.randomUUID(), request.displayName().trim() + "'s Organization"));
        memberships.save(new OrganizationMembership(UUID.randomUUID(), organization.getId(), user.getId(), Role.OWNER));
        auditEvents.save(new AuditEvent(organization.getId(), user.getId(), "USER_REGISTERED", ipAddress, null));
        rateLimiter.clear(ipAddress);
        return createSession(user, organization, Role.OWNER);
    }

    @Transactional
    public SessionResult login(AuthDtos.LoginRequest request, String ipAddress) {
        String email = normalizeEmail(request.email());
        if (!rateLimiter.allow(ipAddress)) throw new ApiException(HttpStatus.TOO_MANY_REQUESTS, "AUTH_RATE_LIMITED", "Too many authentication attempts. Try again later.");
        UserAccount user = users.findByEmail(email).orElse(null);
        if (user == null || !user.isEnabled() || !passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            rateLimiter.recordFailure(ipAddress);
            throw new ApiException(HttpStatus.UNAUTHORIZED, "INVALID_CREDENTIALS", "Invalid email or password.");
        }
        OrganizationMembership membership = memberships.findByUserId(user.getId()).stream().findFirst()
            .orElseThrow(() -> new ApiException(HttpStatus.FORBIDDEN, "NO_ORGANIZATION", "The account has no active organization."));
        rateLimiter.clear(ipAddress);
        auditEvents.save(new AuditEvent(membership.getOrganizationId(), user.getId(), "USER_LOGGED_IN", ipAddress, null));
        Organization organization = organizations.findById(membership.getOrganizationId()).orElseThrow();
        return createSession(user, organization, membership.getRole());
    }

    @Transactional
    public void logout(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) return;
        sessions.findByTokenHash(hash(rawToken)).ifPresent(session -> { session.revoke(); sessions.save(session); });
    }

    @Transactional(readOnly = true)
    public SessionLookup lookup(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) return null;
        AuthSession session = sessions.findByTokenHash(hash(rawToken)).orElse(null);
        if (session == null || !session.isActive(Instant.now())) return null;
        UserAccount user = users.findById(session.getUserId()).orElse(null);
        if (user == null || !user.isEnabled()) return null;
        OrganizationMembership membership = memberships.findByUserId(user.getId()).stream().findFirst().orElse(null);
        if (membership == null) return null;
        return new SessionLookup(session, user, membership);
    }

    @Transactional(readOnly = true)
    public SessionLookup lookupFromPrincipal(AuthenticatedUser principal) {
        if (principal == null) throw new ApiException(HttpStatus.UNAUTHORIZED, "AUTHENTICATION_REQUIRED", "Authentication is required.");
        UserAccount user = users.findById(principal.userId()).orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "AUTHENTICATION_REQUIRED", "Authentication is required."));
        OrganizationMembership membership = memberships.findByOrganizationIdAndUserId(principal.organizationId(), principal.userId()).orElseThrow(() -> new ApiException(HttpStatus.FORBIDDEN, "ORGANIZATION_ACCESS_DENIED", "Organization access is not available."));
        return new SessionLookup(null, user, membership);
    }

    @Transactional(readOnly = true)
    public List<AuthDtos.OrganizationResponse> organizationsFor(AuthenticatedUser principal) {
        if (principal == null) throw new ApiException(HttpStatus.UNAUTHORIZED, "AUTHENTICATION_REQUIRED", "Authentication is required.");
        return memberships.findByUserId(principal.userId()).stream()
            .map(membership -> organizations.findById(membership.getOrganizationId())
                .map(org -> new AuthDtos.OrganizationResponse(org.getId(), org.getName(), membership.getRole()))
                .orElse(null))
            .filter(java.util.Objects::nonNull)
            .toList();
    }

    @Transactional(readOnly = true)
    public AuthDtos.OrganizationResponse organizationFor(AuthenticatedUser principal, UUID organizationId) {
        if (principal == null) throw new ApiException(HttpStatus.UNAUTHORIZED, "AUTHENTICATION_REQUIRED", "Authentication is required.");
        OrganizationMembership membership = memberships.findByOrganizationIdAndUserId(organizationId, principal.userId())
            .orElseThrow(() -> new ApiException(HttpStatus.FORBIDDEN, "ORGANIZATION_ACCESS_DENIED", "Organization access is not available."));
        Organization organization = organizations.findById(organizationId)
            .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "ORGANIZATION_NOT_FOUND", "Organization was not found."));
        return new AuthDtos.OrganizationResponse(organization.getId(), organization.getName(), membership.getRole());
    }

    private SessionResult createSession(UserAccount user, Organization organization, Role role) {
        byte[] tokenBytes = new byte[32]; RANDOM.nextBytes(tokenBytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
        Instant expiresAt = Instant.now().plus(SESSION_TTL);
        sessions.save(new AuthSession(UUID.randomUUID(), user.getId(), hash(token), expiresAt));
        return new SessionResult(token, new AuthDtos.SessionResponse(new AuthDtos.UserResponse(user.getId(), user.getEmail(), user.getDisplayName()), new AuthDtos.OrganizationResponse(organization.getId(), organization.getName(), role), expiresAt));
    }

    static String normalizeEmail(String email) { return email.trim().toLowerCase(Locale.ROOT); }
    static String hash(String value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch (Exception exception) { throw new IllegalStateException("SHA-256 unavailable", exception); }
    }
    public record SessionResult(String token, AuthDtos.SessionResponse response) { }
    public record SessionLookup(AuthSession session, UserAccount user, OrganizationMembership membership) { }
}
