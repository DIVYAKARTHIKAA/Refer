package com.dynamiccode.medilogix.service;

import java.util.List;

import com.dynamiccode.medilogix.dto.request.UserRequest;
import com.dynamiccode.medilogix.dto.response.UserResponse;
import com.dynamiccode.medilogix.model.UserModel;

public interface UserService {

    List<UserResponse> getAllUsers();

    UserResponse getUser(Long uid);

    UserResponse updateUser(UserRequest request, Long uid);

    

	

	

	boolean deleteProduct(Long uid);



}