# Spring Security Calibration

Java 21 · Spring Boot 4.0.9 · Maven

## Run the tests

Open the project directory in IntelliJ IDEA as a Maven project, select JDK 21, and run `SecurityCalibrationTest`. From a terminal, use `mvn clean verify`. Tests supply their own bootstrap credentials.

## Start locally

Set these environment variables to three passwords of your choice (each 1–72 UTF-8 bytes). In IntelliJ, add them under **Run → Edit Configurations → Environment variables** for `CalibrationApplication`.

- `CALIBRATION_ACCOUNTS_ALICE_PASSWORD`
- `CALIBRATION_ACCOUNTS_BOB_PASSWORD`
- `CALIBRATION_ACCOUNTS_REGISTRAR_PASSWORD`

Run `CalibrationApplication` in IntelliJ or use `mvn spring-boot:run` with the variables set. The application listens on port 8080.

## Try it in Postman

1. Send `POST http://localhost:8080/api/auth/token` with **Body → raw → JSON**. Use `{"username":"alice","password":"<your Alice password>"}`.
2. Copy `accessToken` from the response. Set **Authorization → Bearer Token** on the enrollment requests and paste that value.
3. Try both student paths, then repeat without the token. You can log in as `registrar` to test the privileged role.

| Request or identity | Expected result |
| --- | --- |
| Valid login | 200 with an access token and a 900-second lifetime |
| Unknown user or wrong password | 401 with the same JSON error |
| No token, expired token, or invalid signature | 401 on enrollment requests |
| Alice requests `GET /api/students/alice/enrollments` | 200 with Alice's courses |
| Alice requests `GET /api/students/bob/enrollments` | 403 |
| Registrar requests either student's enrollments | 200 |

## How the drills are implemented

| Drill | Mechanism |
| --- | --- |
| Stateless filter chain | Spring Security uses `SessionCreationPolicy.STATELESS` and disables the request cache. Only `POST /api/auth/token` permits anonymous API access. |
| Password hashing | Bootstrap passwords are encoded before insertion into the account store. `DaoAuthenticationProvider` verifies credentials through `BCryptPasswordEncoder.matches`. |
| Signed token | Nimbus signs each JWT with HS256. The resource-server filter verifies the signature, issuer, and expiration, then builds the security context from the verified token. |
| Service authorization | `@EnableMethodSecurity` activates the `@PreAuthorize` rule on `EnrollmentService.findByStudentId`. A direct service test checks denial for an authenticated caller with the wrong role. |
| Horizontal access | The same rule matches a student's requested ID against their authenticated username. A real bearer-token test proves Alice receives 403 for Bob's enrollments, while Bob receives 200 for that same resource. |

Accounts and sample enrollments live in memory. The application creates a fresh signing key at startup, so tokens expire after 15 minutes or become invalid on restart.
