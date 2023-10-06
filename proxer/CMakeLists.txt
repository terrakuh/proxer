
file(GLOB_RECURSE sources "${CMAKE_CURRENT_SOURCE_DIR}/*.[ch]pp")

add_library(proxer ${sources})
add_library(proxer::proxer ALIAS proxer)
target_link_libraries(proxer PUBLIC Boost::boost curlio::curlio OpenSSL::SSL)
target_include_directories(proxer PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>" $<INSTALL_INTERFACE:include>)

target_compile_features(proxer PUBLIC cxx_std_20)

install(TARGETS proxer EXPORT ${PROJECT_NAME}-targets)
install(DIRECTORY . DESTINATION include/proxer FILES_MATCHING PATTERN "*.hpp")
