/**
 * @file   tests.cpp
 * @author Alex Ott <alex_ott@securecomputing.com>
 * @date   $Date$
 * Revision: $Revision$
 * 
 * Copyright: WebWasherAG 
 * 
 * @brief  
 * 
 * 
 */

#include <boost/test/minimal.hpp>

#include "common.h"


int test_main( int /*argc*/, char* /*argv*/[] ) {

	{
		HashData h;
		h.majorVersion=1;
		h.minorVersion=2;
		h.hashes.insert("AAAAAA");
		h.hashes.insert("BBBBBB");
		h.hashes.insert("CCCCCC");
		std::ofstream ofs("test.dat");
		boost::archive::text_oarchive oa(ofs);
		oa << h;
	}

	{
		HashData h;
		std::ifstream ifs("test.dat", std::ios::binary);
		boost::archive::text_iarchive ia(ifs);
		ia >> h;
		BOOST_REQUIRE( h.majorVersion == 1 );
		BOOST_REQUIRE( h.minorVersion == 2 );
	}

	
	return 0;
}
