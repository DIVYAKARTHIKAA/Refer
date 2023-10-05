package com.dynamiccode.medilogix.dto.info;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Docinfo {

	private int doctorId;
    private String doctorName;
}
