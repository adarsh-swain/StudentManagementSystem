package com.student.service;

import java.util.List;

import com.student.payload.StudentDto;

public interface StudentService {
	
	public StudentDto regStudent(StudentDto studentDto);
	
	public List<StudentDto> getAllStudent();
	
	public StudentDto getStudentByName(Long id);
	
	public StudentDto updateStudent(Long id, StudentDto studentDto);
	
	public void deleteStudent(Long id);

	
}
