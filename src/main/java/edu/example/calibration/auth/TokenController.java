package edu.example.calibration.auth;

import java.util.Map;

import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
class TokenController {

    private final TokenService tokenService;

    TokenController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @PostMapping("/token")
    ResponseEntity<TokenService.TokenResponse> token(@RequestBody Credentials credentials) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(tokenService.issue(credentials));
    }

    @ExceptionHandler(AuthenticationException.class)
    ResponseEntity<Map<String, String>> invalidCredentials() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .cacheControl(CacheControl.noStore())
                .body(Map.of("error", "Invalid credentials"));
    }
}
