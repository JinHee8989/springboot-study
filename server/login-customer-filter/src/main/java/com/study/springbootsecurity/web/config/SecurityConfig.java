package com.study.springbootsecurity.web.config;

import com.study.springbootsecurity.web.student.StudentManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableWebSecurity(debug = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final StudentManager studentManager;

    public SecurityConfig(StudentManager studentManager) {
        this.studentManager = studentManager;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth){
        auth.authenticationProvider(studentManager);    //studentManager가 provider가 됨
    }


}
