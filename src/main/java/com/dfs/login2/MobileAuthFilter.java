package com.dfs.login2;

import java.io.IOException;
import java.util.AbstractMap;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

public class MobileAuthFilter extends OncePerRequestFilter {
    private AuthenticationManager authenticationManager;

    public MobileAuthFilter(AuthenticationManager authenticationManager) {
        super();
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        var deviceId = request.getHeader("Device-Id");
        var fidoKey = request.getHeader("Fido-Key");
        var fidoValue = request.getHeader("Fido-Value");

        // No mobile auth headers, continue to username/password auth
        if (deviceId == null) {
            filterChain.doFilter(request, response);
            return;
        }
        
        var authRequest = UsernamePasswordAuthenticationToken.unauthenticated(deviceId, new AbstractMap.SimpleEntry<>(fidoKey, fidoValue));
        try {
            var authentication = this.authenticationManager.authenticate(authRequest);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            filterChain.doFilter(request, response);
        }
        catch (AccessDeniedException ex) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, ex.getMessage());
        }
    }
    
}
