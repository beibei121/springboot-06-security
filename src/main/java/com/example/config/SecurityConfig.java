package com.example.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * @program: springboot-06-security
 * @description:
 * @author: beibei
 * @create: 2022-03-08 20:01
 */
//AOP: 拦截器！
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //首页所有人都可以访问，功能页只有对应有权限的人才能访问
        //请求授权的规则

        http.authorizeRequests()
                .antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasRole("vip1")
                .antMatchers("/level2/**").hasRole("vip2")
                .antMatchers("/level3/**").hasRole("vip3");

        //没有权限会到登录页面,需要开启登录的页面
        http.formLogin().loginPage("/toLogin");

        http.csrf().disable();//关闭csrf
        //注销：注销过后，跳到首页
        http.logout().deleteCookies("remove")
                .logoutSuccessUrl("/");
        //开启记住我功能
        http.rememberMe().rememberMeParameter("remember");//默认2周
    }

    //认证
    //密码编码：PasswordEncoder
    //在Spring Secutiry 5.0+ 新增了很多的加密方式
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        //这些数据应该从数据库中读
        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
                .withUser("bei").password(new BCryptPasswordEncoder().encode("123456")).roles("vip2","vip3")
                .and()
                .withUser("root").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1","vip2","vip3")
                .and()
                .withUser("guest").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1");
    }
}