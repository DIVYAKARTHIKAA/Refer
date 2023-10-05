package com.dynamiccode.medilogix.controller;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.dynamiccode.medilogix.model.DoctorModel;
import com.dynamiccode.medilogix.service.DoctorService;

@RestController
@RequestMapping(value="/doctor")
@CrossOrigin("*")
public class DoctorController{
	@Autowired
	private DoctorService doctorService;
	
	@GetMapping(value="/getall")
	private ResponseEntity<Object> getDoctors() 
	{
		List<DoctorModel> doctorList = doctorService.getDoctors();
		return new ResponseEntity<>(doctorList, HttpStatus.OK);
	}

	@GetMapping(value="/getbyid/{doctorId}")
	private ResponseEntity<Object> getDoctorbyid(@PathVariable int doctorId) 
	{
		boolean isDoctorExistbyid = doctorService.isDoctorExistbyid(doctorId);
		if (isDoctorExistbyid)
		{
		DoctorModel doctorModel = doctorService.getDoctorbyid(doctorId);
		return new ResponseEntity<>(doctorModel, HttpStatus.OK);
		}
		else
		{
			return new ResponseEntity<>("ID not found",HttpStatus.OK);
		}
	}
	
	@GetMapping(value="/getbyname/{doctorName}")
	private ResponseEntity<Object> getDoctorbyname(@PathVariable String doctorName) 
	{
		List<DoctorModel> doctorModel = doctorService.getDoctorbyname(doctorName);
		return new ResponseEntity<>(doctorModel, HttpStatus.OK);
	}
	
	
	
	
	@PostMapping(value="/add")
	public String createDoctor(@RequestBody DoctorModel doctorModel)
	{
		boolean isDoctorExist = doctorService.isDoctorExist(doctorModel.getDoctorName());
		if(isDoctorExist)
			return "Doctor exists already";
		else {
		doctorModel = doctorService.createDoctor(doctorModel);
		return "Doctor added";}
	}
		
	
	@DeleteMapping(value="/delete")
	public ResponseEntity<Object> deleteDoctor(@RequestParam int doctorId)
	{
			doctorService.deleteDoctor(doctorId);
			return new ResponseEntity<>("""
                    R.I.P.
                    Cause of Death : DoctorPageModel Deletion\
                    """, HttpStatus.OK);
	}
	
	
	@PutMapping(value="/edit/{doctorId}")
	public ResponseEntity<Object> updateDoctor(@PathVariable int doctorId, @RequestBody DoctorModel doctorModel)
	{
			doctorModel.setDoctorId(doctorId);
			doctorService.updateDoctor(doctorModel);
			return new ResponseEntity<>("DoctorPageModel details are updated successsfully !", HttpStatus.OK);
	}
	
}