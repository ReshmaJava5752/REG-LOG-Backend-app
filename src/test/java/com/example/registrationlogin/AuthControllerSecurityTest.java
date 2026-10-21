package com.example.registrationlogin;

import com.example.registrationlogin.controller.AuthController;
import com.example.registrationlogin.security.JwtAuthenticationEntryPoint;
import com.example.registrationlogin.security.JwtAuthenticationFilter;
import com.example.registrationlogin.security.JwtUtils;
import com.example.registrationlogin.security.TokenBlacklistService;
import com.example.registrationlogin.service.UserService;
import com.example.registrationlogin.repository.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class AuthControllerSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private UserService userService;

    @Test
    @DisplayName("Protected endpoint GET /profile without token should return HTTP 401 Unauthorized")
    void getProfile_WithoutToken_Returns401() throws Exception {
        mockMvc.perform(get("/profile"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").value("Unauthorized: Please provide a valid authentication token."));
    }

    @Test
    @DisplayName("Protected endpoint GET /api/auth/profile without token should return HTTP 401 Unauthorized")
    void getApiAuthProfile_WithoutToken_Returns401() throws Exception {
        mockMvc.perform(get("/api/auth/profile"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").value("Unauthorized: Please provide a valid authentication token."));
    }

    @Test
    @DisplayName("Protected endpoint PUT /change-password without token should return HTTP 401 Unauthorized")
    void changePassword_WithoutToken_Returns401() throws Exception {
        mockMvc.perform(put("/change-password")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"currentPassword\":\"OldPass@123\",\"newPassword\":\"NewPass@123\",\"confirmPassword\":\"NewPass@123\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Public health check GET /status should be accessible without token (HTTP 200)")
    void getStatus_Public_Returns200() throws Exception {
        mockMvc.perform(get("/status"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    @DisplayName("Public health check GET /api/auth/status should be accessible without token (HTTP 200)")
    void getApiAuthStatus_Public_Returns200() throws Exception {
        mockMvc.perform(get("/api/auth/status"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    @DisplayName("Public endpoint POST /forgot-password should be accessible without token (HTTP 200)")
    void forgotPassword_Public_Returns200() throws Exception {
        mockMvc.perform(post("/forgot-password")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"identifier\":\"user@example.com\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    @DisplayName("Public endpoint POST /api/reg should be routed and accessible without token")
    void postApiReg_Public_IsRouted() throws Exception {
        mockMvc.perform(post("/api/reg")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"fullName\":\"Test User\",\"email\":\"test@example.com\",\"mobileNumber\":\"9876543210\",\"password\":\"Password@123\",\"confirmPassword\":\"Password@123\"}"))
                .andExpect(status().isCreated());
    }

    @Test
    @DisplayName("Public endpoint POST /api/login should be routed and accessible without token")
    void postApiLogin_Public_IsRouted() throws Exception {
        mockMvc.perform(post("/api/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"identifier\":\"test@example.com\",\"password\":\"Password@123\"}"))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Protected endpoint GET /api/profile without token should return HTTP 401 Unauthorized")
    void getApiProfile_WithoutToken_Returns401() throws Exception {
        mockMvc.perform(get("/api/profile"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").value("Unauthorized: Please provide a valid authentication token."));
    }
}
