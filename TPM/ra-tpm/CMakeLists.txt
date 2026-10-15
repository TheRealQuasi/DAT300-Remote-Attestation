project (optee_example_ra_ftpm C)

set (SRC host/main.c)

add_executable (${PROJECT_NAME} ${SRC})

target_link_libraries (${PROJECT_NAME} PRIVATE tss2-esys tss2-mu tss2-rc tss2-tctildr)

install (TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})