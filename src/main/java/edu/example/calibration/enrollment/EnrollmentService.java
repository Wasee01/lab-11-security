package edu.example.calibration.enrollment;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.parameters.P;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class EnrollmentService {

    private final EnrollmentRepository repository;

    EnrollmentService(EnrollmentRepository repository) {
        this.repository = repository;
    }

    @PreAuthorize("hasRole('REGISTRAR') or (hasRole('STUDENT') and #studentId == authentication.name)")
    public List<Enrollment> findByStudentId(@P("studentId") String studentId) {
        return repository.findByStudentId(studentId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Student not found"));
    }
}
