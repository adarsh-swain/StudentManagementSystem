package com.student.serviceImpl;

import java.util.List;
import java.util.stream.Collectors;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.student.entity.Student;
import com.student.exception.ResourceNotFoundException;
import com.student.payload.StudentDto;
import com.student.repository.StudentRepository;
import com.student.service.StudentService;

@Service
public class StudentServiceImpl implements StudentService {

	@Autowired
	private StudentRepository studentRepository;
	
	@Autowired
	private ModelMapper modelMapper;
	
	@Autowired
	private PasswordEncoder passwordEncoder;

	@Override
	public StudentDto regStudent(StudentDto studentDto) {
		Student student = modelMapper.map(studentDto, Student.class);
		String passEncode = passwordEncoder.encode(studentDto.getPassword());
		student.setPassword(passEncode);
		Student saveStudent = studentRepository.save(student);
		return modelMapper.map(saveStudent, StudentDto.class);
	}

	@Override
	public List<StudentDto> getAllStudent() {
		List<Student> getAllStudent = studentRepository.findAll();
		return getAllStudent.stream().map(student-> modelMapper.map(student, StudentDto.class)).collect(Collectors.toList());
	}
	
	@Override
	public StudentDto getStudentByName(Long id) {
		Student student = studentRepository.findById(id).orElseThrow(()->new ResourceNotFoundException("Student Id NotFound : "+ id) );
		return modelMapper.map(student, StudentDto.class);
	}

	@Override
	public StudentDto updateStudent(Long id, StudentDto studentDto) {
		Student student = studentRepository.findById(id).orElseThrow(()->new ResourceNotFoundException("Student Id NotFound : "+ id) );
		student.setAddress(studentDto.getAddress());
		student.setRollNo(studentDto.getRollNo());
		Student updateStudent = studentRepository.save(student);
		return modelMapper.map(updateStudent, StudentDto.class);
	}

	@Override
	public void deleteStudent(Long id) {
		Student student = studentRepository.findById(id).orElseThrow(()->new ResourceNotFoundException("Student Id NotFound : "+ id) );
		studentRepository.delete(student);
	}

	
	
	
//	public Student regStudent(Student student) {
//		Student regStud = studentRepository.save(student);
//		return regStud;
//	}
//
//	public List<Student> getAllStudent() {
//		List<Student> allStudent = studentRepository.findAll();
//		return allStudent;
//	}
//
//	public List<Student> getStudentByName(String username) {
//		List<Student> getByName = studentRepository.findByUsername(username);
//		return getByName;
//	}
//
//	public String deleteStudent(Long id) {
//		Optional<Student> stud = studentRepository.findById(id);
//		if (stud.isPresent()) {
//			Student student = stud.get();
//			studentRepository.delete(student);
//		}
//
//		return "Student Deleted SuccessFully !!";
//	}
//	
//	public Student updateStudent(Long id,Student student) {
//		Optional<Student> getStud = studentRepository.findById(id);
//		if(getStud.isPresent()) {
//			Student upstud = getStud.get();
//			upstud.setAddress(student.getAddress());
//			upstud.setRollNo(student.getRollNo());
//			upstud.setUsername(student.getUsername());
//			Student upStudent = studentRepository.save(upstud);
//			return upStudent;
//		}
//		return null;
//	}

}
