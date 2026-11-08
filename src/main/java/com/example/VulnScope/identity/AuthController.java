package com.example.VulnScope.identity;

import java.time.Duration;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
    private final AuthService authService;
    private final boolean secureCookie;
    public AuthController(AuthService authService, @Value("${COOKIE_SECURE:false}") boolean secureCookie) { this.authService=authService; this.secureCookie=secureCookie; }

    @GetMapping("/csrf")
    public CsrfResponse csrf(CsrfToken token) { return new CsrfResponse(token.getToken()); }

    @PostMapping("/register")
    public AuthDtos.SessionResponse register(@Valid @RequestBody AuthDtos.RegisterRequest request, HttpServletRequest http, HttpServletResponse response) {
        return issue(authService.register(request, clientIp(http)), response);
    }

    @PostMapping("/login")
    public AuthDtos.SessionResponse login(@Valid @RequestBody AuthDtos.LoginRequest request, HttpServletRequest http, HttpServletResponse response) {
        return issue(authService.login(request, clientIp(http)), response);
    }

    @PostMapping("/logout")
    public void logout(@CookieValue(name=SessionAuthenticationFilter.COOKIE_NAME, required=false) String token, HttpServletResponse response) {
        authService.logout(token);
        response.addHeader("Set-Cookie", ResponseCookie.from(SessionAuthenticationFilter.COOKIE_NAME, "").httpOnly(true).secure(secureCookie).sameSite("Strict").path("/").maxAge(Duration.ZERO).build().toString());
    }

    @GetMapping("/me")
    public AuthDtos.UserResponse me(@AuthenticationPrincipal AuthenticatedUser principal) {
        AuthService.SessionLookup lookup = authService.lookupFromPrincipal(principal);
        return new AuthDtos.UserResponse(lookup.user().getId(), lookup.user().getEmail(), lookup.user().getDisplayName());
    }

    private AuthDtos.SessionResponse issue(AuthService.SessionResult result, HttpServletResponse response) {
        response.addHeader("Set-Cookie", ResponseCookie.from(SessionAuthenticationFilter.COOKIE_NAME, result.token()).httpOnly(true).secure(secureCookie).sameSite("Strict").path("/").maxAge(Duration.ofHours(8)).build().toString());
        return result.response();
    }
    private String clientIp(HttpServletRequest request) { return request.getRemoteAddr(); }
    public record CsrfResponse(String token) { }
}
