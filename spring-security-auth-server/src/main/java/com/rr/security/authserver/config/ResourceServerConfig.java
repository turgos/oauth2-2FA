package com.rr.security.authserver.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;


@EnableResourceServer
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ResourceServerConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	CustomDetailsService customDetailsService;
	
	
	@Bean
	public PasswordEncoder encoder() {
		return new BCryptPasswordEncoder();
	}
	
	
	@Bean(name = "authenticationManager")
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

	@Override
	  public void configure(WebSecurity web) throws Exception {
	    web.ignoring().antMatchers("/webjars/**");
	    web.ignoring().antMatchers("/css/**","/fonts/**","/libs/**");
	  }
	  
	  @Override
	  protected void configure(HttpSecurity http) throws Exception { // @formatter:off
	      http.requestMatchers()
	          .antMatchers("/login", "/oauth/authorize", "/secure/two_factor_authentication","/exit", "/resources/**")
	          .and()
	          .authorizeRequests()
	          .anyRequest()
	          .authenticated()
	          .and()
	          .formLogin().loginPage("/login")
	          .permitAll();
	  } // @formatter:on
	


    @Override
    @Autowired // <-- This is crucial otherwise Spring Boot creates its own
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

//        auth//.parentAuthenticationManager(authenticationManager)
//                .inMemoryAuthentication()
//                .withUser("demo")
//                .password("demo")
//                .roles("USER");
    	
    	auth.userDetailsService(customDetailsService).passwordEncoder(encoder());
    }
}
