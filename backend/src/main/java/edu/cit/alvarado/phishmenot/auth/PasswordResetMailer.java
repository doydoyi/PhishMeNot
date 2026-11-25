package edu.cit.alvarado.phishmenot.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;

/**
 * Emails password reset links over SMTP (configured with SPRING_MAIL_* environment variables).
 * Without SMTP settings, the link is written to the server log so the flow can still be tested locally.
 */
@Component
public class PasswordResetMailer {

    private static final Logger log = LoggerFactory.getLogger(PasswordResetMailer.class);

    private final ObjectProvider<JavaMailSender> mailSender;
    private final String from;

    public PasswordResetMailer(ObjectProvider<JavaMailSender> mailSender,
            @Value("${app.mail-from:${spring.mail.username:no-reply@phishmenot.local}}") String from) {
        this.mailSender = mailSender;
        this.from = from;
    }

    public void sendResetLink(String to, String name, String link, long validMinutes) {
        JavaMailSender sender = mailSender.getIfAvailable();
        if (sender == null) {
            // shortcut: dev-only fallback when SMTP is not configured; set SPRING_MAIL_HOST in any shared deployment
            log.warn("Email is not configured (SPRING_MAIL_HOST). Password reset link for {}: {}", to, link);
            return;
        }
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(to);
        message.setSubject("Reset your PhishMeNot password");
        message.setText("""
                Hi %s,

                We received a request to reset your PhishMeNot password. Open this link to choose a new one:

                %s

                The link works once and expires in %d minutes. If you did not ask for this, ignore this email;
                your password will not change.

                - PhishMeNot""".formatted(name, link, validMinutes));
        try {
            sender.send(message);
        } catch (MailException e) {
            log.error("Could not send password reset email to {}", to, e);
        }
    }
}
