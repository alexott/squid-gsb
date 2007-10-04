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
#include <vector>

#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/string.hpp>

#include <boost/filesystem.hpp>
namespace fs = boost::filesystem;

struct HashData {
	int majorVersion;
	int minorVersion;
	
	typedef std::set<std::string> HashSet;
	HashSet hashes;

	friend class boost::serialization::access;

	template<class Archive> void serialize(Archive & ar, const unsigned int version) {
        ar & majorVersion;
        ar & minorVersion;
        ar & hashes;
    }
    HashData() : majorVersion(0), minorVersion(0) { }
	
} ;
BOOST_CLASS_TRACKING(HashData, boost::serialization::track_never)

typedef std::vector<std::string> StringVector;


#endif /* _COMMON_H */

