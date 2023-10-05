package com.dynamiccode.medilogix.repository;


import java.util.List;

import org.springframework.data.repository.CrudRepository;

import com.dynamiccode.medilogix.model.DoctorModel;
public interface DocRepo  extends CrudRepository<DoctorModel, Integer>
{

	boolean existsByDoctorNameIgnoreCase(String doctorName);

    List<DoctorModel> findByDoctorNameContainingIgnoreCase(String doctorName);
}




