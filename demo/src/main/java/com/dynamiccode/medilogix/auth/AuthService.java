package com.dynamiccode.medilogix.auth;

import org.springframework.stereotype.Service;

import com.dynamiccode.medilogix.dto.request.RegisterRequest;

@Service
public interface AuthService {
	
    boolean userRegistration(RegisterRequest request);

    AuthenticationResponse userAuthentication(AuthenticationRequest request);
}