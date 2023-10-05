package com.dynamiccode.medilogix.dto.request;

import com.dynamiccode.medilogix.model.enu.Role;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor



public class UserRequest {
    private String name;
    private String email;
    private String password;
    private Boolean isEnabled;
    private Role role;
}