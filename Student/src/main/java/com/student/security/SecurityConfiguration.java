package com.student.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfiguration {

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http.csrf((csrf) -> csrf.disable())
				.authorizeHttpRequests((auth) -> auth.requestMatchers("/api/getStudent/**").hasRole("USER")
						.requestMatchers("/api/save").permitAll()
						.requestMatchers("/api/allstudent").hasRole("ADMIN").anyRequest().authenticated())
				.formLogin((formLogin) -> formLogin.permitAll());
		return http.build();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public UserDetailsService userDetailsService(PasswordEncoder encoder) {
		UserDetails user = User.withUsername("user").password(encoder.encode("1234")).roles("USER").build();
		UserDetails admin = User.withUsername("admin").password(encoder.encode("1234")).roles("ADMIN").build();
		return new InMemoryUserDetailsManager(user, admin);
	}

}
