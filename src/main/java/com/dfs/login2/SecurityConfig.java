package com.dfs.login2;

import java.io.IOException;
import java.util.ArrayList;

import java.util.logging.LogRecord;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        
        return http
        .csrf(c -> c.disable())
        .antMatcher("/login")
        .addFilterAfter(new CacheFilter(), BasicAuthenticationFilter.class)
        .addFilterBefore(new MobileAuthFilter(new MobileAuthenticationManager()), BasicAuthenticationFilter.class)
        .addFilterAfter(new UsernamePasswordFilter(new UsernamePasswordAuthenticationManager()), BasicAuthenticationFilter.class)
        //.authenticationManager(new CustomAuthenticationManager())
        .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
       // .formLogin().and()
        // .authenticationManager(new CustomAuthenticationManager())
        // .authenticationProvider(new CustomAuthenticationProvider())
        .build();
        // .authorizeRequests(auth -> auth.antMatchers("/login").access(""))
            
        //     .csrf(c -> c.disable())
        //     .httpBasic().and().build();
        // http
        //     .authorizeHttpRequests((authz) -> authz
        //         .anyRequest().authenticated()
        //     )
        //     .httpBasic(withDefaults());
        //return http.build();
    }

    // @Bean
    // public WebSecurityCustomizer webSecurityCustomizer() {
    //     return (web) -> web.ignoring().antMatchers("/swagger-ui");
    // }

}