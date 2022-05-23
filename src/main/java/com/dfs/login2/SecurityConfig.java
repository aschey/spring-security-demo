package com.dfs.login2;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
        .csrf(c -> c.disable())
        .antMatcher("/login")
        .addFilterAfter(new CacheFilter(), BasicAuthenticationFilter.class)
        .addFilterAfter(new MobileAuthFilter(new MobileAuthenticationManager()), BasicAuthenticationFilter.class)
        .addFilterAfter(new UsernamePasswordFilter(new UsernamePasswordAuthenticationManager()), BasicAuthenticationFilter.class)
        .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
        .build();
    }
}