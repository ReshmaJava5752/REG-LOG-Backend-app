package com.example.registrationlogin.security;

import com.example.registrationlogin.entity.User;
import com.example.registrationlogin.repository.UserRepository;
import com.example.registrationlogin.service.SessionService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.Optional;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtils jwtUtils;
    private final TokenBlacklistService tokenBlacklistService;
    private final SessionService sessionService;
    private final UserRepository userRepository;

    @Autowired
    public JwtAuthenticationFilter(JwtUtils jwtUtils,
                                   TokenBlacklistService tokenBlacklistService,
                                   SessionService sessionService,
                                   UserRepository userRepository) {
        this.jwtUtils = jwtUtils;
        this.tokenBlacklistService = tokenBlacklistService;
        this.sessionService = sessionService;
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String token = parseJwt(request);

        // A token is only accepted when it is a valid JWT, has not been revoked in the
        // in-memory list, and still corresponds to an active session in the session store.
        // Tokens issued before persistent sessions were enabled have no session record and
        // remain valid until their own expiry.
        if (token != null
                && jwtUtils.validateToken(token)
                && !tokenBlacklistService.isBlacklisted(token)
                && sessionService.isSessionActive(token)) {
            String identifier = jwtUtils.getIdentifierFromToken(token);
            java.util.Date issuedAt = jwtUtils.getIssuedAtFromToken(token);

            if (identifier != null && (issuedAt == null || !tokenBlacklistService.isUserTokenRevokedBefore(identifier, issuedAt.getTime()))) {
                if (SecurityContextHolder.getContext().getAuthentication() == null) {
                Optional<User> userOptional = userRepository.findByEmailOrMobileNumber(identifier, identifier);

                    if (userOptional.isPresent()) {
                        User user = userOptional.get();
                        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                                user,
                                null,
                                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"))
                        );
                        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                    }
                }
            }
        }

        filterChain.doFilter(request, response);
    }

    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");
        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7).trim();
        }
        return null;
    }
}
