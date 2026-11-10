package edu.example.calibration.auth;

import java.nio.charset.StandardCharsets;

record Credentials(String username, String password) {

    static boolean acceptsPassword(String password) {
        return password != null && !password.isBlank()
                && password.getBytes(StandardCharsets.UTF_8).length <= 72;
    }
}
