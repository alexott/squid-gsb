cmake_minimum_required(VERSION 2.6)
PROJECT(squid-gsb)

# Usage: 
#   cmake . -DCMAKE_INCLUDE_PATH=/home/ott/exp/include -DCMAKE_LIBRARY_PATH=/home/ott/exp/lib
#       -DBOOST_INCLUDEDIR=/home/ott/exp/include -DBOOST_LIBRARYDIR=/home/ott/exp/lib
#

SET(CMAKE_VERBOSE_MAKEFILE ON)

ENABLE_TESTING()

ADD_DEFINITIONS(-g -Wall -ansi -Wno-deprecated -DBOOST_TEST_DYN_LINK)

SET(Boost_USE_STATIC_LIBS OFF)
SET(Boost_USE_MULTITHREAD ON)
SET(Boost_ADDITIONAL_VERSIONS "1.38.0" "1.38" "1.37.0" "1.37" "1.36.0" "1.36")
FIND_PACKAGE(Boost 1.35.0 REQUIRED
  COMPONENTS system filesystem program_options thread serialization regex unit_test_framework)
IF(Boost_FOUND)
  INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIRS})
	LINK_DIRECTORIES(${Boost_LIBRARY_DIRS})
ENDIF(Boost_FOUND)

SET(GSB_CONFDIR "${CMAKE_INSTALL_PREFIX}/etc/squid-gsb" CACHE PATH "Directory with config file")
SET(GSB_STATEDIR "${CMAKE_INSTALL_PREFIX}/var/cache/squid-gsb" CACHE PATH "Directory with data files")

CONFIGURE_FILE(squid-gsb.conf.in ${CMAKE_CURRENT_BINARY_DIR}/squid-gsb.conf)

add_subdirectory(src)


