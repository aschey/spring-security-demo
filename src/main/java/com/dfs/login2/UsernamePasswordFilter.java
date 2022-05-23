package com.dfs.login2;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

public class UsernamePasswordFilter extends OncePerRequestFilter {

    private ObjectMapper objectMapper = new ObjectMapper();
    private AuthenticationManager authenticationManager;

	public UsernamePasswordFilter(AuthenticationManager authenticationManager) {
        super();
        this.authenticationManager = authenticationManager;
	}

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        // Already authenticated
        if (auth != null) {
            filterChain.doFilter(request, response);
        }
       
        var requestString = new String(request.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        var creds = objectMapper.readValue(requestString, Creds.class);
        var authRequest = UsernamePasswordAuthenticationToken.unauthenticated(creds.user, creds.password);
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
