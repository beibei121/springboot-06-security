package com.example.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * @program: springboot-06-security
 * @description:
 * @author: beibei
 * @create: 2022-03-08 19:24
 */
@Controller
public class RouterController {

    @RequestMapping({"/","/index"})
    public String index(){
        return "index";
    }

    @RequestMapping({"/toLogin"})
    public String toLogin(){
        return "views/login";
    }

    @RequestMapping({"/level1/{id}"})
    public String level1(@PathVariable("id") int id){
        return "views/level1/"+id;
    }
    @RequestMapping({"/level2/{id}"})
    public String level2(@PathVariable("id") int id){
        return "views/level2/"+id;
    }
    @RequestMapping({"/level3/{id}"})
    public String level3(@PathVariable("id") int id){
        return "views/level3/"+id;
    }

}