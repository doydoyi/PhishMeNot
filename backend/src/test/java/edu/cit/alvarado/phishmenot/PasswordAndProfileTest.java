package edu.cit.alvarado.phishmenot;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oidcLogin;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.LocalDateTime;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import edu.cit.alvarado.phishmenot.auth.GoogleProfile;
import edu.cit.alvarado.phishmenot.auth.PasswordResetMailer;
import edu.cit.alvarado.phishmenot.auth.PasswordResetTokenRepository;
import edu.cit.alvarado.phishmenot.auth.UserAccountService;
import edu.cit.alvarado.phishmenot.user.Role;
import edu.cit.alvarado.phishmenot.user.User;
import edu.cit.alvarado.phishmenot.user.UserRepository;

/** Increment 2: email/password accounts, profile management, change password, forgot/reset password. */
@SpringBootTest
@AutoConfigureMockMvc
class PasswordAndProfileTest {

    @Autowired MockMvc mvc;
    @Autowired UserRepository userRepository;
    @Autowired PasswordResetTokenRepository tokenRepository;
    @Autowired UserAccountService googleAccounts;
    @MockitoBean PasswordResetMailer mailer;

    @BeforeEach
    void clean() {
        tokenRepository.deleteAll();
        userRepository.deleteAll();
    }

    private ResultActions postJson(String url, String json, MockHttpSession session) throws Exception {
        return mvc.perform(post(url).session(session).with(csrf()).contentType(MediaType.APPLICATION_JSON).content(json));
    }

    private ResultActions putJson(String url, String json, MockHttpSession session) throws Exception {
        return mvc.perform(put(url).session(session).with(csrf()).contentType(MediaType.APPLICATION_JSON).content(json));
    }

    private MockHttpSession registerAndLogin(String email, String password) throws Exception {
        MockHttpSession session = new MockHttpSession();
        postJson("/api/auth/register", """
                {"name":"Maria Santos","email":"%s","password":"%s","confirmPassword":"%s"}"""
                .formatted(email, password, password), session).andExpect(status().isCreated());
        login(email, password, session).andExpect(status().isOk());
        return session;
    }

    private ResultActions login(String email, String password, MockHttpSession session) throws Exception {
        return postJson("/api/auth/login", """
                {"email":"%s","password":"%s"}""".formatted(email, password), session);
    }

    @Test
    void registrationHashesPasswordAndAssignsUserRole() throws Exception {
        postJson("/api/auth/register", """
                {"name":"Maria Santos","email":"Maria@Example.com","password":"secret123","confirmPassword":"secret123"}""",
                new MockHttpSession())
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.email").value("maria@example.com"))
                .andExpect(jsonPath("$.role").value("USER"))
                .andExpect(jsonPath("$.hasPassword").value(true))
                .andExpect(jsonPath("$.passwordHash").doesNotExist());

        User saved = userRepository.findByEmailIgnoreCase("maria@example.com").orElseThrow();
        assertThat(saved.getPasswordHash()).startsWith("$2").isNotEqualTo("secret123");
        assertThat(saved.getGoogleId()).isNull();
    }

    @Test
    void registrationValidatesInputAndRejectsDuplicates() throws Exception {
        postJson("/api/auth/register", """
                {"name":"","email":"not-an-email","password":"short","confirmPassword":"short"}""", new MockHttpSession())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors.name").exists())
                .andExpect(jsonPath("$.fieldErrors.email").exists())
                .andExpect(jsonPath("$.fieldErrors.password").exists());
        postJson("/api/auth/register", """
                {"name":"A","email":"a@example.com","password":"secret123","confirmPassword":"secret124"}""", new MockHttpSession())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("The passwords do not match."));

        registerAndLogin("dup@example.com", "secret123");
        postJson("/api/auth/register", """
                {"name":"B","email":"DUP@example.com","password":"secret123","confirmPassword":"secret123"}""", new MockHttpSession())
                .andExpect(status().isConflict());

        // an email already used by a Google account cannot be claimed with a password
        googleAccounts.registerOrLogin(new GoogleProfile("g-1", "google@example.com", true, "G User", null));
        postJson("/api/auth/register", """
                {"name":"C","email":"google@example.com","password":"secret123","confirmPassword":"secret123"}""", new MockHttpSession())
                .andExpect(status().isConflict());
        assertThat(userRepository.count()).isEqualTo(2);
    }

    @Test
    void registrationNeverGrantsAdminEvenForAdminEmails() throws Exception {
        // boss@example.com is in app.admin-emails; an unverified password signup must not become ADMIN
        registerAndLogin("boss@example.com", "secret123");
        assertThat(userRepository.findByEmailIgnoreCase("boss@example.com").orElseThrow().getRole()).isEqualTo(Role.USER);
    }

    @Test
    void loginStartsSessionAndRejectsBadCredentials() throws Exception {
        MockHttpSession session = registerAndLogin("login@example.com", "secret123");
        mvc.perform(get("/api/me").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("login@example.com"));
        mvc.perform(get("/api/admin/dashboard").session(session)).andExpect(status().isForbidden());

        login("login@example.com", "wrong-pass1", new MockHttpSession())
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid email or password."));
        login("nobody@example.com", "secret123", new MockHttpSession()).andExpect(status().isUnauthorized());

        // Google-only accounts have no password to log in with
        googleAccounts.registerOrLogin(new GoogleProfile("g-2", "gonly@example.com", true, "G", null));
        login("gonly@example.com", "anything1", new MockHttpSession()).andExpect(status().isUnauthorized());
    }

    @Test
    void userCanViewAndEditOwnProfileWithValidation() throws Exception {
        MockHttpSession session = registerAndLogin("p@example.com", "secret123");
        putJson("/api/me/profile", """
                {"name":"  Maria Clara  ","profilePictureUrl":"https://example.com/me.png"}""", session)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("Maria Clara"))
                .andExpect(jsonPath("$.profilePictureUrl").value("https://example.com/me.png"));
        assertThat(userRepository.findByEmailIgnoreCase("p@example.com").orElseThrow().getName()).isEqualTo("Maria Clara");

        putJson("/api/me/profile", """
                {"name":"","profilePictureUrl":"javascript:alert(1)"}""", session)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors.name").exists())
                .andExpect(jsonPath("$.fieldErrors.profilePictureUrl").exists());

        mvc.perform(put("/api/me/profile").with(csrf()).contentType(MediaType.APPLICATION_JSON)
                .content("{\"name\":\"x\"}")).andExpect(status().isUnauthorized());
    }

    @Test
    void profileUpdateOnlyChangesTheSignedInUser() throws Exception {
        User other = userRepository.saveAndFlush(new User("g-other", "other@example.com", "Other", null, Role.USER));
        MockHttpSession session = registerAndLogin("me@example.com", "secret123");
        // extra fields such as an id or email are ignored: the account always comes from the session
        putJson("/api/me/profile", """
                {"id":%d,"email":"other@example.com","name":"Hacked"}""".formatted(other.getUserId()), session)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("me@example.com"));
        assertThat(userRepository.findById(other.getUserId()).orElseThrow().getName()).isEqualTo("Other");
    }

    @Test
    void changePasswordVerifiesCurrentAndRetiresOldPassword() throws Exception {
        MockHttpSession session = registerAndLogin("c@example.com", "secret123");

        putJson("/api/me/password", """
                {"currentPassword":"wrong1234","newPassword":"newpass456","confirmPassword":"newpass456"}""", session)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Your current password is incorrect."));
        putJson("/api/me/password", """
                {"currentPassword":"secret123","newPassword":"newpass456","confirmPassword":"newpass457"}""", session)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("The new passwords do not match."));
        putJson("/api/me/password", """
                {"currentPassword":"secret123","newPassword":"weak","confirmPassword":"weak"}""", session)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors.newPassword").exists());
        putJson("/api/me/password", """
                {"currentPassword":"secret123","newPassword":"secret123","confirmPassword":"secret123"}""", session)
                .andExpect(status().isBadRequest());

        putJson("/api/me/password", """
                {"currentPassword":"secret123","newPassword":"newpass456","confirmPassword":"newpass456"}""", session)
                .andExpect(status().isOk());

        login("c@example.com", "secret123", new MockHttpSession()).andExpect(status().isUnauthorized());
        login("c@example.com", "newpass456", new MockHttpSession()).andExpect(status().isOk());
    }

    @Test
    void googleOnlyUserIsToldToUseForgotPasswordInsteadOfChange() throws Exception {
        googleAccounts.registerOrLogin(new GoogleProfile("g-3", "g3@example.com", true, "G3", null));
        mvc.perform(put("/api/me/password")
                        .with(oidcLogin().idToken(t -> t.subject("g-3")).authorities(new SimpleGrantedAuthority("ROLE_USER")))
                        .with(csrf()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"currentPassword\":\"x\",\"newPassword\":\"newpass456\",\"confirmPassword\":\"newpass456\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.containsString("Forgot password")));
    }

    private String requestResetAndCaptureToken(String email) throws Exception {
        postJson("/api/auth/forgot-password", "{\"email\":\"" + email + "\"}", new MockHttpSession())
                .andExpect(status().isOk());
        ArgumentCaptor<String> link = ArgumentCaptor.forClass(String.class);
        verify(mailer, org.mockito.Mockito.atLeastOnce()).sendResetLink(eq(email), anyString(), link.capture(), anyLong());
        assertThat(link.getValue()).startsWith("http://localhost:5173/reset-password?token=");
        return link.getValue().substring(link.getValue().indexOf("token=") + 6);
    }

    @Test
    void forgotPasswordResetIsSingleUseAndHashed() throws Exception {
        registerAndLogin("r@example.com", "secret123");
        String token = requestResetAndCaptureToken("r@example.com");
        assertThat(tokenRepository.findAll()).allSatisfy(t -> assertThat(t.getUsedAt()).isNull());
        assertThat(tokenRepository.findByTokenHash(token)).isEmpty(); // only the hash is stored

        postJson("/api/auth/reset-password", """
                {"token":"%s","newPassword":"reset789x","confirmPassword":"reset789x"}""".formatted(token), new MockHttpSession())
                .andExpect(status().isOk());
        login("r@example.com", "secret123", new MockHttpSession()).andExpect(status().isUnauthorized());
        login("r@example.com", "reset789x", new MockHttpSession()).andExpect(status().isOk());

        // the same link cannot be used twice
        postJson("/api/auth/reset-password", """
                {"token":"%s","newPassword":"again789x","confirmPassword":"again789x"}""".formatted(token), new MockHttpSession())
                .andExpect(status().isBadRequest());
    }

    @Test
    void newResetLinkReplacesOldOneAndExpiredLinksFail() throws Exception {
        registerAndLogin("e@example.com", "secret123");
        String first = requestResetAndCaptureToken("e@example.com");
        String second = requestResetAndCaptureToken("e@example.com");
        assertThat(second).isNotEqualTo(first);
        postJson("/api/auth/reset-password", """
                {"token":"%s","newPassword":"reset789x","confirmPassword":"reset789x"}""".formatted(first), new MockHttpSession())
                .andExpect(status().isBadRequest());

        // expire the remaining token
        tokenRepository.saveAll(tokenRepository.findAll().stream().peek(t -> org.springframework.test.util.ReflectionTestUtils
                .setField(t, "expiresAt", LocalDateTime.now().minusMinutes(1))).toList());
        postJson("/api/auth/reset-password", """
                {"token":"%s","newPassword":"reset789x","confirmPassword":"reset789x"}""".formatted(second), new MockHttpSession())
                .andExpect(status().isBadRequest());
    }

    @Test
    void forgotPasswordDoesNotRevealUnknownEmails() throws Exception {
        postJson("/api/auth/forgot-password", "{\"email\":\"ghost@example.com\"}", new MockHttpSession())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.startsWith("If an account exists")));
        verify(mailer, never()).sendResetLink(anyString(), anyString(), anyString(), anyLong());
    }

    @Test
    void googleUserCanCreatePasswordThroughForgotPassword() throws Exception {
        googleAccounts.registerOrLogin(new GoogleProfile("g-4", "g4@example.com", true, "G4", null));
        String token = requestResetAndCaptureToken("g4@example.com");
        postJson("/api/auth/reset-password", """
                {"token":"%s","newPassword":"mypass123","confirmPassword":"mypass123"}""".formatted(token), new MockHttpSession())
                .andExpect(status().isOk());
        login("g4@example.com", "mypass123", new MockHttpSession())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.googleLinked").value(true));
    }

    @Test
    void endpointsRequireCsrfToken() throws Exception {
        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"a@example.com\",\"password\":\"x\"}")).andExpect(status().isForbidden());
    }
}
