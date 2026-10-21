package com.example.registrationlogin.dto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the {@link UserResponse} contract, in particular how the {@code createdAt} and
 * {@code updatedAt} timestamps are exposed to API clients.
 */
class UserResponseTest {

    @Test
    @DisplayName("Should expose both createdAt and updatedAt when they are supplied")
    void fullConstructor_ExposesBothTimestamps() {
        LocalDateTime createdAt = LocalDateTime.of(2026, 1, 15, 10, 30, 0);
        LocalDateTime updatedAt = LocalDateTime.of(2026, 2, 20, 8, 0, 0);

        UserResponse response = new UserResponse(1L, "John Doe", "john@example.com",
                "9876543210", createdAt, updatedAt);

        assertEquals(createdAt, response.getCreatedAt());
        assertEquals(updatedAt, response.getUpdatedAt());
    }

    @Test
    @DisplayName("Should fall back updatedAt to createdAt for the shorter constructors")
    void shorterConstructors_FallBackUpdatedAtToCreatedAt() {
        LocalDateTime createdAt = LocalDateTime.of(2026, 1, 15, 10, 30, 0);

        UserResponse withoutMobile = new UserResponse(1L, "John Doe", "john@example.com", createdAt);
        UserResponse withMobile = new UserResponse(1L, "John Doe", "john@example.com",
                "9876543210", createdAt);

        assertEquals(createdAt, withoutMobile.getCreatedAt());
        assertEquals(createdAt, withoutMobile.getUpdatedAt());
        assertEquals(createdAt, withMobile.getCreatedAt());
        assertEquals(createdAt, withMobile.getUpdatedAt());
    }
}
