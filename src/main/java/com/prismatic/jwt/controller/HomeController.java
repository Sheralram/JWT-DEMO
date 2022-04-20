package com.prismatic.jwt.controller;

import com.prismatic.jwt.model.JwtRequest;
import com.prismatic.jwt.model.JwtResponse;
import com.prismatic.jwt.service.UserService;
import com.prismatic.jwt.utility.JWTUtility;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {
    @Autowired
    private JWTUtility jwtUtility;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserService userService;


    @GetMapping("/")
    public String getHome(){
        return "Welcome to Prismatic!!";
    }

    @PostMapping(value = "/authenticate")
    public JwtResponse authenticate(
            @RequestBody JwtRequest jwtRequest
    ) throws Exception {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            jwtRequest.getUserName(),
                            jwtRequest.getPassword()
                    )
            );
        } catch (BadCredentialsException exception) {
            throw new Exception("INVALID CREDENTIALS", exception);
        }
        final UserDetails userDetails
                = userService.loadUserByUsername(jwtRequest.getUserName());

        final String token = jwtUtility.generateToken(userDetails);

        return new JwtResponse(token);
    }

}
