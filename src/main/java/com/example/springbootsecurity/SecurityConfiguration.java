package com.example.springbootsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	//override below method to configure in-memory users instead of default or users from properties file.
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		//super.configure(auth);
		//Now due to below code, the default users create by spring security or the default users 
		//that we created in Application.properties will not be working hence forth.
		auth.inMemoryAuthentication()
		.withUser("mohiteas").password("mohiteas").roles("USER")
		.and().withUser("admin").password("admin").roles("ADMIN");
	}
	
	@Bean
	public PasswordEncoder getPasswordEncoder() {
		return NoOpPasswordEncoder.getInstance();
	}
	
	
	//override below method to configure authorization for the urls.
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		//super.configure(http);
		// --only admin can access
		//http.authorizeRequests() .antMatchers("/**") .hasRole("ADMIN")
		//.and().formLogin(); //'*'-->means current level & '**'-->means nested level
		
		http.authorizeRequests()
		.antMatchers("/admin").hasRole("ADMIN") //--only admin can access 'admin url'
		.antMatchers("/user").hasAnyRole("USER","ADMIN") //--user or admin can access 'user url'
		.antMatchers("/","static/css","static/jss").permitAll() //any one can access
		.and().formLogin();
		
	}
	
}
