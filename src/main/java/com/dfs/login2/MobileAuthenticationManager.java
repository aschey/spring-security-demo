package com.dfs.login2;

import java.util.ArrayList;
import java.util.AbstractMap.SimpleEntry;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class MobileAuthenticationManager implements AuthenticationManager {
    @Override
    public Authentication authenticate(Authentication authentication) 
      throws AuthenticationException {
      
        var deviceId = authentication.getName();
        var keyValue = (SimpleEntry<String, String>)authentication.getCredentials();
        
        // Call auth API
        if (deviceId.equals("bob")) {
            return new UsernamePasswordAuthenticationToken(
                deviceId, keyValue, new ArrayList<>());
        } 
        else {
            throw new CustomAuthenticationException("test");
        }
    }
}
