PROJECT(gsb_src)

SET(USED_LIBS ${Boost_SYSTEM_LIBRARY} ${Boost_THREAD_LIBRARY} ${Boost_REGEX_LIBRARY}
  ${Boost_PROGRAM_OPTIONS_LIBRARY} ${Boost_FILESYSTEM_LIBRARY}
  ${Boost_SERIALIZATION_LIBRARY})

INCLUDE_DIRECTORIES(${gsb_src_SOURCE_DIR})
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_BINARY_DIR})

CONFIGURE_FILE(gsb-conf.h.in ${CMAKE_CURRENT_BINARY_DIR}/gsb-conf.h)

ADD_EXECUTABLE(gsb_updater common.h gsb-updater.cpp common.cpp gsb-conf.h)
TARGET_LINK_LIBRARIES(gsb_updater ${USED_LIBS})

ADD_EXECUTABLE(gsb_redirector common.h gsb-redirector.cpp md5.cpp common.cpp gsb-conf.h)
TARGET_LINK_LIBRARIES(gsb_redirector ${USED_LIBS})

ADD_EXECUTABLE(tests tests.cpp common.h)
TARGET_LINK_LIBRARIES(tests ${USED_LIBS})
ADD_TEST(tests tests)

INSTALL(TARGETS gsb_updater gsb_redirector
	RUNTIME DESTINATION bin)


