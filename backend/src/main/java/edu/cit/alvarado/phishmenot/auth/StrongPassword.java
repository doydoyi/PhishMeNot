package edu.cit.alvarado.phishmenot.auth;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/** Password policy for new passwords: 8-72 characters (BCrypt's limit) with at least one letter and one number. */
@NotBlank(message = "Password is required")
@Size(min = 8, max = 72, message = "Password must be 8 to 72 characters long")
@Pattern(regexp = "^(?=.*[A-Za-z])(?=.*\\d).*$", message = "Password must contain at least one letter and one number")
@Target({ElementType.FIELD, ElementType.PARAMETER, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = {})
public @interface StrongPassword {
    String message() default "Password does not meet the requirements";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}
