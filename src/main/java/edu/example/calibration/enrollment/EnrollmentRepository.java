package edu.example.calibration.enrollment;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.stereotype.Repository;

@Repository
class EnrollmentRepository {

    private final Map<String, List<Enrollment>> enrollments = Map.of(
            "alice", List.of(new Enrollment("CS101", "Introduction to Programming")),
            "bob", List.of(new Enrollment("DB201", "Database Design")));

    Optional<List<Enrollment>> findByStudentId(String studentId) {
        return Optional.ofNullable(enrollments.get(studentId));
    }
}
