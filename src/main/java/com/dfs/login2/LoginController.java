package com.dfs.login2;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
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
    public String login(@RequestBody Creds creds) {
        // Call SSO API, translation API, etc
       return creds.user;
    }

    @GetMapping("/")
    public String Index() {
        return "this is the index";
    }
}
