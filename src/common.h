/**
 * @file   common.h
 * @author Alex Ott <alexott@gmail.com>
 *
 * @brief  Commmon definitions
 *
 *
 */

#ifndef _COMMON_H
#define _COMMON_H 1

#include <set>
#include <string>
#include <fstream>
#include <deque>

#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/string.hpp>

//#define BOOST_FILESYSTEM_VERSION 2

#include <boost/filesystem.hpp>
namespace fs = boost::filesystem;

#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>

#include <boost/program_options.hpp>
namespace po = boost::program_options;

struct HashData {
	int majorVersion;
	int minorVersion;
	std::string name;

	typedef std::set<std::string> HashSet;
	HashSet hashes;

	friend class boost::serialization::access;

	template<class Archive> void serialize(Archive & ar, const unsigned int version) {
        ar & majorVersion;
        ar & minorVersion;
		ar & name;
        ar & hashes;
    }
    HashData() : majorVersion(1), minorVersion(-1) { }

} ;
BOOST_CLASS_TRACKING(HashData, boost::serialization::track_never)

typedef std::deque<std::string> StringVector;

bool parseOptions(int argc, char** argv, po::variables_map& cfg);

#endif /* _COMMON_H */

