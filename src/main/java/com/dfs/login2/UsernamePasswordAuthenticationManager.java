package com.dfs.login2;

import java.util.ArrayList;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class UsernamePasswordAuthenticationManager implements AuthenticationManager {

    @Override
    public Authentication authenticate(Authentication authentication) 
      throws AuthenticationException {
      
        var name = authentication.getName();
        var password = authentication.getCredentials().toString();
        // Call auth API
        if ((name.equals("bob") || name.equals("joe")) && (password.equals("bob") || password.equals("joe"))) {
            return new UsernamePasswordAuthenticationToken(
                name, password, new ArrayList<>());
        } 
        else {
            throw new CustomAuthenticationException("auth failure");
        }
    }
}
