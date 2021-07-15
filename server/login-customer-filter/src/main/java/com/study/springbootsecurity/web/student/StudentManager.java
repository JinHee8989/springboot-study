package com.study.springbootsecurity.web.student;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Set;

@Component
public class StudentManager implements AuthenticationProvider, InitializingBean {

   private HashMap<String, Student> studentDB = new HashMap<>();    //원래는 DB를 다녀와야하지만 지금은 인메모리객체로 테스트

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken)authentication;

        if(studentDB.containsKey(token.getName())){
            Student student = studentDB.get(token.getName());
            return StudentAuthenticationToken.builder()
                    .principal(student)
                    .details(student.getUsername()) //인증대상에 대한 정보를 담음
                    .authenticated(true)
                    .build();
        }
        return null;    //처리할 수 없는 authentication은 null로 해야함(토큰을 false로 해선 안됨- 내가 처리한게 되므로)
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication == UsernamePasswordAuthenticationToken.class;
    }

    @Override
    public void afterPropertiesSet() throws Exception { //임의로 초기화 후 데이터 넣어줌

        Set.of(
                new Student("hong","홍길동",Set.of(new SimpleGrantedAuthority("ROLE_STUDENT"))),
                new Student("kang","강아지",Set.of(new SimpleGrantedAuthority("ROLE_STUDENT"))),
                new Student("rang","호랑이",Set.of(new SimpleGrantedAuthority("ROLE_STUDENT")))

        ).forEach( s ->
                studentDB.put(s.getId(),s)
        );


    }
}
