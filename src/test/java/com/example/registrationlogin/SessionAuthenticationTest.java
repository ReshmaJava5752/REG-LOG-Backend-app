package com.example.registrationlogin;

import com.example.registrationlogin.dto.UserResponse;
import com.example.registrationlogin.entity.User;
import com.example.registrationlogin.entity.UserSession;
import com.example.registrationlogin.repository.UserRepository;
import com.example.registrationlogin.repository.UserSessionRepository;
import com.example.registrationlogin.security.JwtUtils;
import com.example.registrationlogin.service.UserService;
import com.example.registrationlogin.util.TokenHasher;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Verifies that the persistent session store is consulted on protected requests and that a
 * revoked session is rejected with HTTP 401 Unauthorized.
 *
 * <p>The real session store logic runs; only the {@code UserSessionRepository} and
 * {@code UserRepository} interfaces are mocked, so the test neither reads nor writes any
 * database row.</p>
 */
@SpringBootTest
@AutoConfigureMockMvc
class SessionAuthenticationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtUtils jwtUtils;

    @MockBean
    private UserService userService;

    @MockBean
    private UserSessionRepository sessionRepository;

    @MockBean
    private UserRepository userRepository;

    private User knownUser() {
        User user = new User("John Doe", "john@example.com", "9876543210", "$2a$10$hashed");
        user.setId(42L);
        user.setCreatedAt(LocalDateTime.now());
        user.setUpdatedAt(LocalDateTime.now());
        return user;
    }

    private UserSession sessionFor(String token, boolean revoked) {
        UserSession session = new UserSession(42L, TokenHasher.sha256Hex(token),
                LocalDateTime.now().minusHours(1), LocalDateTime.now().plusHours(1));
        if (revoked) {
            session.revoke();
        }
        return session;
    }

    @Test
    @DisplayName("Protected endpoint GET /profile should return HTTP 401 when the session was revoked")
    void profile_WithRevokedSession_Returns401() throws Exception {
        String token = jwtUtils.generateToken("john@example.com");
        when(sessionRepository.findFirstByTokenHashOrderByIdDesc(TokenHasher.sha256Hex(token)))
                .thenReturn(Optional.of(sessionFor(token, true)));

        mockMvc.perform(get("/profile").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.success").value(false));

        verify(userRepository, never()).findByEmailOrMobileNumber(anyString(), anyString());
    }

    @Test
    @DisplayName("Protected endpoint GET /profile should succeed when the session is still active")
    void profile_WithActiveSession_Succeeds() throws Exception {
        String token = jwtUtils.generateToken("john@example.com");
        when(sessionRepository.findFirstByTokenHashOrderByIdDesc(TokenHasher.sha256Hex(token)))
                .thenReturn(Optional.of(sessionFor(token, false)));
        when(userRepository.findByEmailOrMobileNumber("john@example.com", "john@example.com"))
                .thenReturn(Optional.of(knownUser()));
        when(userService.getUserByIdentifier("john@example.com"))
                .thenReturn(new UserResponse(42L, "John Doe", "john@example.com", "9876543210",
                        LocalDateTime.now(), LocalDateTime.now()));

        mockMvc.perform(get("/profile").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    @DisplayName("Protected endpoint GET /api/profile should return HTTP 401 when the session was revoked")
    void apiProfile_WithRevokedSession_Returns401() throws Exception {
        String token = jwtUtils.generateToken("john@example.com");
        when(sessionRepository.findFirstByTokenHashOrderByIdDesc(TokenHasher.sha256Hex(token)))
                .thenReturn(Optional.of(sessionFor(token, true)));

        mockMvc.perform(get("/api/profile").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Protected endpoint PUT /change-password should return HTTP 401 when the session was revoked")
    void changePassword_WithRevokedSession_Returns401() throws Exception {
        String token = jwtUtils.generateToken("john@example.com");
        when(sessionRepository.findFirstByTokenHashOrderByIdDesc(TokenHasher.sha256Hex(token)))
                .thenReturn(Optional.of(sessionFor(token, true)));

        mockMvc.perform(put("/change-password")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"currentPassword\":\"OldPass@123\",\"newPassword\":\"NewPass@123\",\"confirmPassword\":\"NewPass@123\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Public routes should not consult the session store")
    void status_RemainsPublic() throws Exception {
        mockMvc.perform(get("/status"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));

        verify(sessionRepository, never()).findFirstByTokenHashOrderByIdDesc(anyString());
    }
}
