package com.dynamiccode.medilogix.dto.request;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DocRequest {
private int doctorId;
private String doctorName;
private String patName;
private String doctordept;
}



