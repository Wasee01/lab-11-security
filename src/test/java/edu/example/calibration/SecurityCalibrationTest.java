package edu.example.calibration;

import java.time.Instant;
import java.util.List;

import com.jayway.jsonpath.JsonPath;
import edu.example.calibration.enrollment.EnrollmentService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {
        "calibration.accounts.alice.password=alice-test-password",
        "calibration.accounts.bob.password=bob-test-password",
        "calibration.accounts.registrar.password=registrar-test-password"
})
@AutoConfigureMockMvc
class SecurityCalibrationTest {

    private static final String TOKEN_ENDPOINT = "/api/auth/token";
    private static final String ALICE_ENROLLMENTS = "/api/students/alice/enrollments";
    private static final String BOB_ENROLLMENTS = "/api/students/bob/enrollments";

    @Autowired
    private MockMvc mvc;

    @Autowired
    private UserDetailsService accounts;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtEncoder jwtEncoder;

    @Autowired
    private JwtDecoder jwtDecoder;

    @Autowired
    private EnrollmentService enrollmentService;

    @Test
    void anonymousApiRequestIsUnauthorizedWithoutCreatingSession() throws Exception {
        var result = mvc.perform(get(ALICE_ENROLLMENTS))
                .andExpect(status().isUnauthorized())
                .andExpect(header().doesNotExist(HttpHeaders.SET_COOKIE))
                .andReturn();

        assertThat(result.getRequest().getSession(false)).isNull();
        mvc.perform(get(TOKEN_ENDPOINT)).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/unmapped")).andExpect(status().isUnauthorized());
    }

    @Test
    void accountStoreContainsOnlyMatchingBcryptHashes() {
        for (String username : List.of("alice", "bob", "registrar")) {
            String rawPassword = username + "-test-password";
            String storedPassword = accounts.loadUserByUsername(username).getPassword();

            assertThat(storedPassword).startsWith("$2").isNotEqualTo(rawPassword);
            assertThat(passwordEncoder.matches(rawPassword, storedPassword)).isTrue();
            assertThat(passwordEncoder.matches("wrong-password", storedPassword)).isFalse();
        }
    }

    @Test
    void signedLoginTokenAuthenticatesRequestWithoutCreatingSession() throws Exception {
        String token = tokenFor("alice");
        var jwt = jwtDecoder.decode(token);

        assertThat(jwt.getHeaders()).containsEntry("alg", "HS256");
        assertThat(jwt.getSubject()).isEqualTo("alice");
        assertThat(jwt.getExpiresAt()).isEqualTo(jwt.getIssuedAt().plusSeconds(900));

        var result = mvc.perform(get(ALICE_ENROLLMENTS).header(HttpHeaders.AUTHORIZATION, bearer(token)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].courseCode").value("CS101"))
                .andExpect(header().doesNotExist(HttpHeaders.SET_COOKIE))
                .andReturn();

        assertThat(result.getRequest().getSession(false)).isNull();
        mvc.perform(get(ALICE_ENROLLMENTS)).andExpect(status().isUnauthorized());
    }

    @Test
    void unknownUserAndWrongPasswordHaveIdenticalUnauthorizedResponses() throws Exception {
        var wrongPassword = login("alice", "wrong-password")
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Invalid credentials"))
                .andReturn().getResponse();

        var unknownUser = login("unknown", "wrong-password")
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse();

        assertThat(unknownUser.getContentAsString()).isEqualTo(wrongPassword.getContentAsString());
        assertThat(unknownUser.getHeaderNames()).containsExactlyInAnyOrderElementsOf(wrongPassword.getHeaderNames());
        for (String header : unknownUser.getHeaderNames()) {
            assertThat(unknownUser.getHeaders(header)).isEqualTo(wrongPassword.getHeaders(header));
        }
    }

    @Test
    void rejectsTokenWithAlteredSignature() throws Exception {
        String token = tokenFor("alice");
        int signatureStart = token.lastIndexOf('.') + 1;
        char replacement = token.charAt(signatureStart) == 'A' ? 'B' : 'A';
        String tampered = token.substring(0, signatureStart) + replacement + token.substring(signatureStart + 1);

        mvc.perform(get(ALICE_ENROLLMENTS).header(HttpHeaders.AUTHORIZATION, bearer(tampered)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void rejectsExpiredTokenEvenWithValidSignature() throws Exception {
        Instant now = Instant.now();
        var claims = JwtClaimsSet.builder()
                .issuer("spring-security-calibration")
                .subject("alice")
                .claim("roles", List.of("STUDENT"))
                .issuedAt(now.minusSeconds(901))
                .expiresAt(now.minusSeconds(1))
                .build();
        var header = JwsHeader.with(MacAlgorithm.HS256).build();
        String token = jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();

        mvc.perform(get(ALICE_ENROLLMENTS).header(HttpHeaders.AUTHORIZATION, bearer(token)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(username = "alice", roles = "VISITOR")
    void serviceRejectsWrongRoleEvenForMatchingUsername() {
        assertThatThrownBy(() -> enrollmentService.findByStudentId("alice"))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    @WithMockUser(username = "alice", roles = "STUDENT")
    void serviceRejectsStudentDirectlyWhenTargetBelongsToAnotherStudent() {
        assertThatThrownBy(() -> enrollmentService.findByStudentId("bob"))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void studentReadingAnotherStudentsEnrollmentsReceivesForbidden() throws Exception {
        String aliceToken = tokenFor("alice");

        mvc.perform(get(BOB_ENROLLMENTS).header(HttpHeaders.AUTHORIZATION, bearer(aliceToken)))
                .andExpect(status().isForbidden());

        String bobToken = tokenFor("bob");
        mvc.perform(get(BOB_ENROLLMENTS).header(HttpHeaders.AUTHORIZATION, bearer(bobToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].courseCode").value("DB201"));
    }

    @Test
    void registrarCanReadAnotherStudentsEnrollments() throws Exception {
        String token = tokenFor("registrar");

        mvc.perform(get(BOB_ENROLLMENTS).header(HttpHeaders.AUTHORIZATION, bearer(token)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].courseCode").value("DB201"));
    }

    private String tokenFor(String username) throws Exception {
        var result = login(username, username + "-test-password")
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"))
                .andExpect(header().doesNotExist(HttpHeaders.SET_COOKIE))
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").value(900))
                .andReturn();

        assertThat(result.getRequest().getSession(false)).isNull();
        return JsonPath.read(result.getResponse().getContentAsString(), "$.accessToken");
    }

    private ResultActions login(String username, String password) throws Exception {
        return mvc.perform(post(TOKEN_ENDPOINT)
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"username":"%s","password":"%s"}
                        """.formatted(username, password)));
    }

    private String bearer(String token) {
        return "Bearer " + token;
    }
}
