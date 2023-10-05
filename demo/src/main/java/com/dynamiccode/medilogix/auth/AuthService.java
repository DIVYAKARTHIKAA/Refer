package com.dynamiccode.medilogix.auth;

import com.dynamiccode.medilogix.auth.AuthenticationRequest;
import com.dynamiccode.medilogix.dto.request.RegisterRequest;
import com.dynamiccode.medilogix.auth.AuthenticationResponse;

public interface AuthService {
    boolean userRegistration(RegisterRequest request);

    AuthenticationResponse userAuthentication(AuthenticationRequest request);
}