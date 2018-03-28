package com.rr.security.authserver.config;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private AuthenticationManager authenticationManager;
    
    @Autowired
    private ClientDetailsService clientDetailsService;

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {

        security.tokenKeyAccess("permitAll()")
                .checkTokenAccess("isAuthenticated()");
    }


    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients
                .inMemory()
                .withClient("ClientId")
                .secret("secret")
                .authorizedGrantTypes("authorization_code")
                .scopes("user_info")
                .authorities(TwoFactorAuthenticationFilter.ROLE_TWO_FACTOR_AUTHENTICATION_ENABLED)
                .autoApprove(true);
    }


    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {

        endpoints
        	.authenticationManager(authenticationManager)
        	.requestFactory(customOAuth2RequestFactory());
    }
    
     
    @Bean
    public DefaultOAuth2RequestFactory customOAuth2RequestFactory(){
    	return new CustomOAuth2RequestFactory(clientDetailsService);
    }
    
    @Bean
    public FilterRegistrationBean twoFactorAuthenticationFilterRegistration(){
    	FilterRegistrationBean registration = new FilterRegistrationBean();
    	registration.setFilter(twoFactorAuthenticationFilter());
    	registration.addUrlPatterns("/oauth/authorize");
    	registration.setName("twoFactorAuthenticationFilter");
    	return registration;
    }
    
	@Bean
    public TwoFactorAuthenticationFilter twoFactorAuthenticationFilter(){
    	return new TwoFactorAuthenticationFilter();
    }
}
