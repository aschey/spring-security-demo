package com.dfs.login2;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;

@RestController
public class LoginController {
    @PostMapping("/login")
    @Parameter(name = "Device-Id", in = ParameterIn.HEADER)
    @Parameter(name = "Fido-Key", in = ParameterIn.HEADER)
    @Parameter(name = "Fido-Value", in = ParameterIn.HEADER)
    //@PostAuthorize("")
    @PreAuthorize("hasPermission(#creds, 'login')")
    public String login(@RequestBody Creds creds, Authentication auth) {
        if (auth == null) {
            return "";
        }
        // Call SSO API, translation API, etc
       return auth.getName();
    }

    @PostMapping("/login2")
    public ResponseEntity<String> login2(@RequestBody Creds creds, 
        @RequestHeader(value = "Device-Id", required = false) String deviceId,
        @RequestHeader(value = "Fido-Key", required = false) String fidoKey,
        @RequestHeader(value = "Fido-Value", required = false) String fidoValue) {

        var user = "";
        if (deviceId != null) {
            // Check biometric auth
            if (deviceId.equals("bob")) {
                user = deviceId;
            } else {
                return new ResponseEntity<>("auth failure", HttpStatus.UNAUTHORIZED);
            }
        } else {
            if ((creds.user.equals("bob") || creds.user.equals("joe")) && (creds.password.equals("bob") || creds.password.equals("joe"))) {
                user = creds.user;
            } else {
                return new ResponseEntity<>("biometric auth failure", HttpStatus.UNAUTHORIZED);
            }
        }

        // Call strong auth API
        if (user.equals("bob")) {
            // Call SSO API, translation API, etc
            return new ResponseEntity<>(creds.user, HttpStatus.OK);
        } else {
            return new ResponseEntity<>("fraud risk", HttpStatus.FORBIDDEN);
        }
    }

    @GetMapping("/")
    public String Index() {
        return "this is the index";
    }
}
