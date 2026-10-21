package com.example.registrationlogin;

import com.example.registrationlogin.service.OtpRateLimiter;
import com.example.registrationlogin.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Verifies that the password-recovery endpoints answer with HTTP 429 Too Many Requests once a
 * client exceeds its limit.
 *
 * <p>The client limit is lowered through a test property so the check needs only a few calls.
 * The property source gives this test its own application context, so the counters of the other
 * test classes are not affected.</p>
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "app.otp.rate-limit.client.max-per-window=2",
        "app.otp.rate-limit.client.window-minutes=15"
})
class OtpRateLimitControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private UserService userService;

    @Autowired
    private OtpRateLimiter otpRateLimiter;

    /**
     * The limiter is a shared singleton for the whole application context, so the counters are
     * cleared before every test. Without this the tests would interfere with each other.
     */
    @BeforeEach
    void resetRateLimiter() {
        otpRateLimiter.reset();
        when(userService.verifyOtp(any())).thenReturn("reset-token");
    }

    @Test
    @DisplayName("POST /forgot-password should answer HTTP 429 once the client limit is reached")
    void forgotPassword_AnswersWithTooManyRequests() throws Exception {
        String body = "{\"identifier\":\"rate-limit@example.com\"}";

        mockMvc.perform(post("/forgot-password").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk());
        mockMvc.perform(post("/forgot-password").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk());

        mockMvc.perform(post("/forgot-password").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(header().exists("Retry-After"));
    }

    @Test
    @DisplayName("POST /verify-otp should answer HTTP 429 once the client limit is reached")
    void verifyOtp_AnswersWithTooManyRequests() throws Exception {
        String body = "{\"identifier\":\"rate-limit@example.com\",\"otpCode\":\"123456\"}";

        mockMvc.perform(post("/verify-otp").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk());
        mockMvc.perform(post("/verify-otp").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk());

        mockMvc.perform(post("/verify-otp").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.success").value(false));
    }

    @Test
    @DisplayName("The rate limit message must not disclose the identifier")
    void tooManyRequests_DoesNotDiscloseTheIdentifier() throws Exception {
        String body = "{\"identifier\":\"secret-account@example.com\"}";

        for (int i = 0; i < 2; i++) {
            mockMvc.perform(post("/forgot-password").contentType(MediaType.APPLICATION_JSON).content(body));
        }

        String response = mockMvc.perform(post("/forgot-password")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isTooManyRequests())
                .andReturn().getResponse().getContentAsString();

        org.junit.jupiter.api.Assertions.assertFalse(response.contains("secret-account@example.com"),
                "The response must not reveal which identifier was limited");
    }

    @Test
    @DisplayName("Other endpoints must not be affected by the recovery rate limit")
    void status_RemainsAvailable() throws Exception {
        mockMvc.perform(post("/forgot-password").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"identifier\":\"one@example.com\"}"));
        mockMvc.perform(post("/forgot-password").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"identifier\":\"two@example.com\"}"));
        mockMvc.perform(post("/forgot-password").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"identifier\":\"three@example.com\"}"));

        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/status"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }
}
