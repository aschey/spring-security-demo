package com.dfs.login2;

import java.io.IOException;
import java.util.AbstractMap;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

public class MobileAuthFilter extends AbstractAuthenticationProcessingFilter {

    private static final AntPathRequestMatcher DEFAULT_ANT_PATH_REQUEST_MATCHER = new AntPathRequestMatcher("/login",
    "POST");

    public MobileAuthFilter(AuthenticationManager authenticationManager) {
        super(DEFAULT_ANT_PATH_REQUEST_MATCHER, authenticationManager);
        setAuthenticationSuccessHandler(new CustomAuthenticationSuccessHandler());
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        super.doFilter(request, response, chain);
        chain.doFilter(request, response);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
        var deviceId = request.getHeader("Device-Id");
        var fidoKey = request.getHeader("Fido-Key");
        var fidoValue = request.getHeader("Fido-Value");

        // No mobile auth headers, continue to username/password auth
        if (deviceId == null) {
            return null;
        }
        
        var authRequest = UsernamePasswordAuthenticationToken.unauthenticated(deviceId, new AbstractMap.SimpleEntry<>(fidoKey, fidoValue));
        var manager  = getAuthenticationManager(); 
        return manager.authenticate(authRequest);
    }
    
}
