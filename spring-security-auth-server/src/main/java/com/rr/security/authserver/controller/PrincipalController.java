package com.rr.security.authserver.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class PrincipalController {


    @GetMapping("/principal")
    public Principal user(Principal principal) {
        return principal;
    }

}
