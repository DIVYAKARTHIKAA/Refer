package com.Dynamiccode.medrec.auth;

import javax.management.relation.Role;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.Dynamiccode.medrec.security.Config.JwtService;
import com.Dynamiccode.medrec.security.user.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor

public class AuthenticationService {
	
	@Autowired
	private UserRepository repository;
	private PasswordEncoder passwordEncoder;
	private JwtService jwtService;
	private AuthenticationManager authenticationManager;
  
  public AuthenticationResponse register(RegisterRequest request) {
	  
	  var user=User.builder()
			  .firstname(request.getFirstname())
			  .lastname(request.getLastname())
			  .email(request.getEmail())
			  .password(passwordEncoder.encode(request.getPassword()))
			  .role(Role.USER)
			  .build();
	  repository.save(user);
	  var jwtToken=jwtService.generateToken(user);
	  
	  
	  return AuthenticationResponse.builder()
			  .token(jwtToken)
			  .build();
	  
  }
  
  public AuthenticationResponse authenticate(AuthenticationRequest request) {
	  authenticationManager.authenticate(
			  new UsernamePasswordAuthenticationToken(
					  request.getEmail(),
					  request.getPassword()
					  )
			  );
	  var user=repository.findByEmail(request.getEmail())
			  .orElseThrow();
	  
  var jwtToken=jwtService.generateToken(user);
	  
	  
	  return AuthenticationResponse.builder()
			  .token(jwtToken)
			  .build();
	  
	  
  }
  
  
 
}