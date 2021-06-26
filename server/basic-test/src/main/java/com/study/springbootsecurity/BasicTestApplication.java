package com.study.springbootsecurity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class BasicTestApplication {
    public static void main(String[] args){
        Person person = Person.builder().name("test").build();    //다른 모듈의 클래스를 레퍼런스하기 (build.gradle에서 해당 모듈을 컴파일해야함)
        SpringApplication.run(BasicTestApplication.class, args);

    }
}
