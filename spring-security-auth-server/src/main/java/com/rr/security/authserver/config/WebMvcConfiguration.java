package com.rr.security.authserver.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

/**
 * Created by sevikm on 3/19/18.
 */

@EnableWebMvc
@Configuration
public class WebMvcConfiguration extends WebMvcConfigurerAdapter {

//  @Override
//  public void addViewControllers(ViewControllerRegistry registry) {
//    registry.addViewController("/login").setViewName("login");
//    //registry.addViewController("/secure/two_factor_authentication").setViewName("loginSecret");
//    registry.setOrder(Ordered.HIGHEST_PRECEDENCE);
//  }

  @Override
  public void addResourceHandlers(ResourceHandlerRegistry registry) {
    registry.addResourceHandler("/webjars/**").addResourceLocations("/webjars/");
  }
}