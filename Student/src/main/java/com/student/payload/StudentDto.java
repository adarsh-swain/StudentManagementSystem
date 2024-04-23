package com.student.payload;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class StudentDto {

	private Long id;
	private String username;
	private String password;
	private String rollNo;
	private String address;
}
