package com.study.springbootsecurity.web.config;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;

@EnableWebSecurity(debug = true)
@EnableGlobalMethodSecurity(prePostEnabled = true)  //MethodSecurity는 우리가 기존에 사용했던 SecurityConfig 설정이 적용되지 않음. 이걸 해줘야 타임리프에서 적용한 security에도 적용됨
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CustomAuthDetails customAuthDetails;  //의존성 주입

    public SecurityConfig(CustomAuthDetails customAuthDetails) {
        this.customAuthDetails = customAuthDetails;
    }


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {  //이렇게 설정해주면 application.yml에 설정해놓은 user는 무시하게됨(로그인 불가)
        auth.inMemoryAuthentication()
                .withUser(
                        User.withDefaultPasswordEncoder().username("user1").password("4321").roles("USER")) //withDefaultPasswordEncoder()는 안전하지않아 테스트때만 사용
                .withUser(
                        User.withDefaultPasswordEncoder().username("admin").password("1111").roles("ADMIN"));
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(request->{
                    request
                            .antMatchers("/**").permitAll()
                            .anyRequest().authenticated()
                            ;
                })

//                .formLogin();        //formLogin()은 UsernamePasswordAuthenticationFilter를 설정해주는것임. formLogin()이면 기본 로그인 화면으로 가게됨.
                .formLogin(
                        login->login.loginPage("/login")    //현재 "/login"은 인증을 해야지만 접속할 수 있으므로
                                                            //다른페이지 가려고함 -> 비인증자 로그인 페이지로 이동->로그인 페이지에서 인증하고 오라고함-> 비인증자 로그인 페이지로 이동-> 무한루프에 빠짐
                        .permitAll()                        //그래서 permitAll()을 무한루프에 안 빠지고 로그인페이지로 접근 가능
                        .defaultSuccessUrl("/",false)   //로그인 후 이동할 페이지 설정(alwaysUse가 false면 로그인 전 액세스한 페이지로 리디렉션, true면 무조건 지정한 페이지로 이동)
                        .failureUrl("/login-error") //로그인 실패했을 때 이동할 페이지 설정
                        .authenticationDetailsSource(customAuthDetails) //userDetails를 customize할 필요가 있을때 설정

                )
                .logout(
                        logout->logout.logoutSuccessUrl("/")    //로그아웃 후 이동할 페이지 설정
                )
                .exceptionHandling(exception -> exception.accessDeniedPage("/access-denied"))   //예외 발생시 이동할 페이지 설정
        ;
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring()  //웹 리소스에 대해서는 스프링 시큐리티 필터가 적용되지 않도록 설정
                .requestMatchers(
                        PathRequest.toStaticResources().atCommonLocations()     //리소스의 static을 몽땅 웹리소스로 잡아주고있음
                );
    }


    @Bean   //(A라는 권한이 B의 권한도 가질수 있도록 설정
    RoleHierarchy roleHierarchy(){
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");
        return roleHierarchy;
    }
}
