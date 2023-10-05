package com.dynamiccode.medilogix.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DocResponse {
	private int doctorId;
	private String doctorName;
	private String patName;
	private String doctordept;

}




 