package com.example.VulnScope.identity;

import java.io.IOException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

public class SessionAuthenticationFilter extends OncePerRequestFilter {
    static final String COOKIE_NAME = "vulnscope_session";
    private final AuthService authService;
    public SessionAuthenticationFilter(AuthService authService) { this.authService = authService; }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        String token = tokenFrom(request);
        AuthService.SessionLookup lookup = authService.lookup(token);
        if (lookup != null) {
            AuthenticatedUser principal = new AuthenticatedUser(lookup.user().getId(), lookup.membership().getOrganizationId(), lookup.membership().getRole());
            var authorities = java.util.List.of(new SimpleGrantedAuthority("ROLE_" + lookup.membership().getRole().name()));
            var authentication = new UsernamePasswordAuthenticationToken(principal, null, authorities);
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        chain.doFilter(request, response);
    }

    static String tokenFrom(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) return null;
        for (Cookie cookie : cookies) if (COOKIE_NAME.equals(cookie.getName())) return cookie.getValue();
        return null;
    }
}
