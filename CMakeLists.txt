cmake_minimum_required(VERSION 3.12)
project(cbox C)

set(CMAKE_C_STANDARD 11)


find_package(PythonLibs 3 REQUIRED)
include_directories(${PYTHON_INCLUDE_DIRS})
add_executable(cbox main.c main.h cbox.c core/syscall.c core/utils.h core/utils.c)
target_link_libraries(cbox ${PYTHON_LIBRARIES})


add_executable(syscall_filter dev/bak/syscall_filter.c dev/sample/config.h dev/sample/seccomp-bpf.h
        dev/sample/syscall-names.h dev/sample/syscall-reporter.c dev/sample/syscall-reporter.h)
target_link_libraries(syscall_filter -lseccomp)

add_executable(syscall_reporter dev/bak/syscall_reporter.c dev/sample/config.h dev/sample/seccomp-bpf.h
        dev/sample/syscall-names.h dev/sample/syscall-reporter.c dev/sample/syscall-reporter.h)
target_link_libraries(syscall_reporter -lseccomp)

add_executable(sample dev/sample/example.c dev/sample/config.h dev/sample/seccomp-bpf.h
        dev/sample/syscall-names.h dev/sample/syscall-reporter.c dev/sample/syscall-reporter.h)


add_executable(course dev/course/main.c dev/course/syscall-names.h)
target_link_libraries(course -lseccomp)
