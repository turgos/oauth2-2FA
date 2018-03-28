package com.rr.security.authserver.controller;


import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import com.rr.security.authserver.config.CustomOAuth2RequestFactory;
import com.rr.security.authserver.config.TwoFactorAuthenticationFilter;

@Controller
@RequestMapping(TwoFactorAuthenticationController.PATH)

public class TwoFactorAuthenticationController {
    private static final Logger LOG = LoggerFactory.getLogger(TwoFactorAuthenticationController.class);
    
    public static final String PATH = "/secure/two_factor_authentication";

    @RequestMapping(method = RequestMethod.GET)
    public String auth(HttpServletRequest request, HttpSession session) {
        if (isAuthenticatedWithAuthority(TwoFactorAuthenticationFilter.ROLE_TWO_FACTOR_AUTHENTICATED)) {
            LOG.debug("User {} already has {} authority - no need to enter code again", TwoFactorAuthenticationFilter.ROLE_TWO_FACTOR_AUTHENTICATED);
            
            //throw ....;
        }
        else if (session.getAttribute(CustomOAuth2RequestFactory.SAVED_AUTHORIZATION_REQUEST_SESSION_ATTRIBUTE_NAME) == null) {
            LOG.debug("Error while entering 2FA code - attribute {} not found in session.", CustomOAuth2RequestFactory.SAVED_AUTHORIZATION_REQUEST_SESSION_ATTRIBUTE_NAME);
            //throw ....;
        }

        LOG.debug("auth() HTML.Get"); 
        
        return "loginSecret"; // Show the form to enter the 2FA secret
    }

    @RequestMapping(method = RequestMethod.POST)
    public String auth(@ModelAttribute(value="secret") String secret, BindingResult result, Model model) {
    	LOG.debug("auth() HTML.Post");
        
    	if (userEnteredCorrect2FASecret(secret)) {
            addAuthority(TwoFactorAuthenticationFilter.ROLE_TWO_FACTOR_AUTHENTICATED);
            return "forward:/oauth/authorize"; // Continue with the OAuth flow
        }
    	
    	model.addAttribute("isIncorrectSecret", true);
        return "loginSecret"; // Show the form to enter the 2FA secret again
    }
    
    private boolean isAuthenticatedWithAuthority(String checkedAuthority){
  
    	return SecurityContextHolder.getContext().getAuthentication().getAuthorities().stream().anyMatch(
                authority -> checkedAuthority.equals(authority.getAuthority())
    			);
    }
    
    private boolean addAuthority(String authority){
    	
    	Collection<SimpleGrantedAuthority> oldAuthorities = (Collection<SimpleGrantedAuthority>)SecurityContextHolder.getContext().getAuthentication().getAuthorities();
    	SimpleGrantedAuthority newAuthority = new SimpleGrantedAuthority(authority);
    	List<SimpleGrantedAuthority> updatedAuthorities = new ArrayList<SimpleGrantedAuthority>();
    	updatedAuthorities.add(newAuthority);
    	updatedAuthorities.addAll(oldAuthorities);

    	SecurityContextHolder.getContext().setAuthentication(
    	        new UsernamePasswordAuthenticationToken(
    	                SecurityContextHolder.getContext().getAuthentication().getPrincipal(),
    	                SecurityContextHolder.getContext().getAuthentication().getCredentials(),
    	                updatedAuthorities)
    	);
    		
    	return true;
    }
    
    private boolean userEnteredCorrect2FASecret(String secret){
    	/* later on, we need to pass a temporary secret for each user and control it here */
    	/* this is just a temporary way to check things are working */
    	
    	if(secret.equals("123"))
    		return true;
    	else;
    		return false;
    }
}
