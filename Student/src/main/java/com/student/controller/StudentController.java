package com.student.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.service.annotation.PutExchange;

import com.student.payload.StudentDto;
import com.student.service.StudentService;

@RestController
@RequestMapping("/api")
public class StudentController {

	@Autowired
	private StudentService studentService;
	
	
	@PostMapping("/save")
	public ResponseEntity<StudentDto>saveStudent(@RequestBody StudentDto studentDto){
		StudentDto regStudent = studentService.regStudent(studentDto);
		return new ResponseEntity<StudentDto>(regStudent, HttpStatus.CREATED);
	}
	
	@GetMapping("/allstudent")
	public ResponseEntity<List<StudentDto>> getAllStudent(){
		List<StudentDto> allStudent = studentService.getAllStudent();
		return ResponseEntity.ok(allStudent);
	}
	
	@GetMapping("/getStudent/{id}")
	public ResponseEntity<StudentDto> getById(@PathVariable Long id){
		StudentDto getStudent = studentService.getStudentByName(id);
		return ResponseEntity.ok(getStudent);
	}
	
	
	@PutMapping("/update/{id}")
	public ResponseEntity<StudentDto> update(@PathVariable Long id, @RequestBody StudentDto studentDto){
		StudentDto updateStudent = studentService.updateStudent(id, studentDto);
		return ResponseEntity.ok(updateStudent);
	}
	
	
	@DeleteMapping("/delete/{id}")
	public ResponseEntity<String> deleteStudent(@PathVariable Long id){
		studentService.deleteStudent(id);
		return ResponseEntity.ok("Deleted SuccessFully");
	}
	
	
	

//	@PostMapping("/save")
//	public Student registration(@RequestBody Student student) {
//		Student regStudent = studentService.regStudent(student);
//		return regStudent;
//	}
//
//	@GetMapping("/allStud")
//	public List<Student> getAllstud() {
//		List<Student> allStudent = studentService.getAllStudent();
//		return allStudent;
//	}
//
//	@GetMapping("/students/{username}")
//	public List<Student> geStudents(@PathVariable String username) {
//		List<Student> studentByName = studentService.getStudentByName(username);
//		return studentByName;
//	}
//
//	@DeleteMapping("/studlt/{id}")
//	public String deleteStud(@PathVariable Long id) {
//		studentService.deleteStudent(id);
//		return "Student Deleted SuccessFully !! ";
//	}
//	
//	@PutMapping("/updateStudent/{id}")
//	public Student updSTudent( @PathVariable Long id,@RequestBody Student student) {
//		Student updateStudent = studentService.updateStudent(id, student);
//		return updateStudent;
//	}

}

