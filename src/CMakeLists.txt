PROJECT(squid-gsb-src)

SET(USED_LIBS ${Boost_SYSTEM_LIBRARY} ${Boost_THREAD_LIBRARY} ${Boost_REGEX_LIBRARY}
  ${Boost_PROGRAM_OPTIONS_LIBRARY} ${Boost_FILESYSTEM_LIBRARY}
  ${Boost_SERIALIZATION_LIBRARY})

#ADD_EXECUTABLE(test-otpc test-otpc.cpp test-otpc-conn.cpp)
#TARGET_LINK_LIBRARIES(test-otpc ${USED_LIBS})

# bin_PROGRAMS = gsb-redirector gsb-updater
# gsb_redirector_SOURCES = common.h gsb-redirector.cpp md5.cpp common.cpp gsb-conf.h
# gsb_updater_SOURCES = common.h gsb-updater.cpp common.cpp gsb-conf.h

ADD_EXECUTABLE(tests tests.cpp common.h)
TARGET_LINK_LIBRARIES(tests ${USED_LIBS})
ADD_TEST(tests tests)
