package com.neon.springsecuritydemo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter
{
    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception
    {
        auth.inMemoryAuthentication()
            .withUser("alice")
            .password("secret")
            .roles("USER")
            .and()
            .withUser("bob")
            .password("password")
            .roles("ADMIN");
    }

    @Bean
    public PasswordEncoder getPasswordEncoder()
    {
        return NoOpPasswordEncoder.getInstance();
    }

    @Override
    public void configure(HttpSecurity http) throws Exception
    {
        http.authorizeRequests()
            .antMatchers("/admin").hasRole("ADMIN") // Add matchers from high restrictive role to least, if we put least at top then it matches all eg., if this "/**" at top it
            // matches all
            .antMatchers("/user").hasAnyRole("USER", "ADMIN")   //spring security doesn't know ADMIN has higher authority, it's just a string, so we have to use hasAnyRole
            .antMatchers("/").permitAll()
            .and().formLogin();
    }
}
