package com.pring.jwt.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.pring.jwt.models.JwtRequest;
import com.pring.jwt.models.JwtResponse;
import com.pring.jwt.services.CustomUserDetailsService;
import com.pring.jwt.utils.JwtUtil;

@RestController
public class JwtController {

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private CustomUserDetailsService customUserDetailsService;

	@Autowired
	private JwtUtil jwtUtil;

	@PostMapping("/token")
	public ResponseEntity<?> generateToken(@RequestBody JwtRequest request) {
		try {
			this.authenticationManager.authenticate(
					new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));
		} catch (UsernameNotFoundException e) {
			e.printStackTrace();
			throw new UsernameNotFoundException("Bad Credentials");
		}
		
		UserDetails userDetails = this.customUserDetailsService.loadUserByUsername(request.getUsername());
		
		String token = this.jwtUtil.generateToken(userDetails);
		
		return ResponseEntity.ok(new JwtResponse(token));
	}

}
