package com.example.registrationlogin.entity;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the JPA lifecycle callbacks that maintain the {@code created_at} and
 * {@code updated_at} columns on the {@code users} table.
 *
 * <p>This test lives in the {@code entity} package so that it can invoke the protected
 * {@code @PrePersist} / {@code @PreUpdate} callbacks directly - the same way Hibernate
 * invokes them during a flush. No database is required.</p>
 */
class UserEntityTest {

    private User newUser() {
        return new User("John Doe", "john@example.com", "9876543210", "$2a$10$hashedPassword");
    }

    @Test
    @DisplayName("Should set both createdAt and updatedAt when the user is inserted")
    void prePersist_SetsCreatedAtAndUpdatedAt() {
        User user = newUser();

        assertNull(user.getCreatedAt(), "createdAt should be unset before the entity is persisted");
        assertNull(user.getUpdatedAt(), "updatedAt should be unset before the entity is persisted");

        user.onCreate();

        assertNotNull(user.getCreatedAt(), "createdAt must be set on insert");
        assertNotNull(user.getUpdatedAt(), "updatedAt must be set on insert");
    }

    @Test
    @DisplayName("Should not overwrite an existing createdAt when the user is inserted")
    void prePersist_KeepsExistingCreatedAt() {
        LocalDateTime originalCreatedAt = LocalDateTime.of(2026, 1, 15, 10, 30, 0);

        User user = newUser();
        user.setCreatedAt(originalCreatedAt);

        user.onCreate();

        assertEquals(originalCreatedAt, user.getCreatedAt(),
                "createdAt must be preserved for rows that already carry a creation timestamp");
        assertNotNull(user.getUpdatedAt(), "updatedAt must still be populated on insert");
    }

    @Test
    @DisplayName("Should bump updatedAt on update while leaving createdAt untouched")
    void preUpdate_BumpsUpdatedAtAndKeepsCreatedAt() {
        LocalDateTime createdAt = LocalDateTime.of(2026, 1, 15, 10, 30, 0);
        LocalDateTime previousUpdatedAt = LocalDateTime.of(2026, 1, 15, 10, 31, 0);

        User user = newUser();
        user.setCreatedAt(createdAt);
        user.setUpdatedAt(previousUpdatedAt);

        user.onUpdate();

        assertEquals(createdAt, user.getCreatedAt(), "createdAt must never change on update");
        assertNotNull(user.getUpdatedAt(), "updatedAt must be set on update");
        assertTrue(user.getUpdatedAt().isAfter(previousUpdatedAt),
                "updatedAt must move forward when the row is updated");
    }
}
