package com.study.springbootsecurity.web.config;

import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Order(1) //securityConfig를 여러개 두는 경우 순서 정해주는 어노테이션임
@EnableWebSecurity(debug = true) //어떤 필터를 거치는지 로그에 찍힘
@EnableGlobalMethodSecurity(prePostEnabled = true) //권한을 체크하게 됨
public class SecurityConfig extends WebSecurityConfigurerAdapter {


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {  //이렇게 설정해주면 application.yml에 설정해놓은 user는 무시하게됨(로그인 불가)
        auth.inMemoryAuthentication()
                .withUser(User.builder().username("user2").password(passwordEncoder().encode("4321")).roles("USER"))
                .withUser(User.builder().username("admin").password(passwordEncoder().encode("1111")).roles("ADMIN"));
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.antMatcher("/api/**");
        http.authorizeRequests((request) -> request.antMatchers("/").permitAll()
                .anyRequest().authenticated()
        );
        http.formLogin();
        http.httpBasic();


    }
}