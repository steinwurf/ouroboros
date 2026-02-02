cmake_minimum_required(VERSION 3.12)
project(ouroboros_benchmark)

add_executable(${PROJECT_NAME} main.cpp)
target_link_libraries(${PROJECT_NAME} steinwurf::ouroboros)
target_link_libraries(${PROJECT_NAME} steinwurf::platform)
target_link_libraries(${PROJECT_NAME} steinwurf::verify)
target_link_libraries(${PROJECT_NAME} steinwurf::expected)
target_link_libraries(${PROJECT_NAME} benchmark)
