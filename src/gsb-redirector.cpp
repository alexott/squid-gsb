/**
 * @file   gsb-redirector.cpp
 * @author Alex Ott <alexott@gmail.com>
 * 
 * @brief  
 * 
 * 
 */

#include "common.h"
#include <iostream>
#include <boost/md5.hpp>

#include<boost/tokenizer.hpp>
typedef boost::tokenizer<boost::char_separator<char> > tokenizer;


struct HashFile {
	HashData h;
	fs::path fname;
	std::string url;
	std::time_t wtime;

	/** 
	 * Update file with hash, using last update time of file
	 * 
	 */
	void updateHash() {
		std::time_t nt;
		if(fs::exists(fname)) {
			if(wtime < (nt=last_write_time(fname))) {
#ifdef DEBUG
				std::cerr << "Going to read " << fname.file_string() << std::endl;
#endif
				std::ifstream ifs(fname.file_string().c_str(), std::ios::binary);
				if(!ifs) {
#ifdef DEBUG
					std::cerr << "Error opening " << fname << std::endl;
#endif
					return;
				}
				boost::archive::text_iarchive ia(ifs);
				ia >> h;
				wtime=nt;
			}
#ifdef DEBUG
		} else {
			std::cerr << fname <<  " doesn't exists" << std::endl;
#endif
		}
	}
	
	HashFile(): fname(""), url(""), wtime(0) { }

	/** 
	 * Check is url in hash?
	 * 
	 * @param sv list of generated url's
	 * @param u new url, that will updated if match found
	 * 
	 * @return if one of url's found in hash
	 */
	bool checkHash(StringVector& sv, std::string& u) {
		if(h.minorVersion == -1)
			return false;
		
		StringVector::iterator it=sv.begin();
		StringVector::iterator itEnd=sv.end();
		HashData::HashSet::iterator hi;
		for(; it != itEnd; ++it) {
			if ((hi=h.hashes.find(*it)) != h.hashes.end()) {
#ifdef DEBUG
			    std::cerr << "Found match in " << h.name
						  << ": " << *it << std::endl;
#endif
				u=url;
				return true;
			}
		}
		return false;
	}
	
} ;

/** 
 * 
 * 
 * @param host 
 * @param hv 
 */
void generateHostVariants(const std::string& host, StringVector& hv) {
	StringVector tsl;
	boost::char_separator<char> hostsep(".");
	tokenizer hosttokens(host, hostsep);
	for (tokenizer::iterator tok_iter = hosttokens.begin();
		 tok_iter != hosttokens.end(); ++tok_iter) {
		tsl.push_front(*tok_iter);
	}
	if(tsl.size() > 1) {
		std::string t=tsl[0];
		unsigned int count=0;
		tsl.pop_front();
		for(StringVector::iterator ti=tsl.begin();
			ti != tsl.end() && count < 4 ; ++ti, ++count  ) {
			t=*ti+"."+t;
			if(t != host)
				hv.push_back(t);
		}
	}
}

/** 
 * 
 * 
 * @param path 
 * @param pv 
 */
void generatePathVariants(const std::string& path, StringVector& pv) {
	StringVector tsl;

	boost::char_separator<char> pathsep("/");
	tokenizer pathtokens(path, pathsep);
	for (tokenizer::iterator tok_iter = pathtokens.begin();
		 tok_iter != pathtokens.end(); ++tok_iter) {
		tsl.push_back(*tok_iter);
	}
	unsigned int maxcount=tsl.size()-1;
	if(maxcount >= 0) {
		std::string t="/";
		unsigned int count=0;
		for(StringVector::iterator ti=tsl.begin();
			ti != tsl.end() && count < 4 ; ++ti, ++count  ) {
			t+=*ti;
			if(count != maxcount)
				t+="/";
 			if(t != path)
 				pv.push_back(t);
		}
	}
}

/** 
 * Generate list of MD5 hashes
 *
 * TODO: use url parser from cpp-netlib?
 *
 * @param url 
 * @param sv 
 * 
 * @return true, if success, false - if no variants generated
 */
bool generateVariants(const std::string& url, StringVector& sv) {
	sv.clear();
	StringVector tv, hv, pv;
	
	std::string t, tm, host, path(""),query("");
 	std::string::size_type idx;
	if(!boost::istarts_with(url,"http://")){
#ifdef DEBUG
		std::cerr << "Not http protocol: " << url << std::endl;
#endif
		return false;
	}
	t=url.substr(7);
	if ((idx=t.find('/')) == std::string::npos) {
		host=t;
	} else {
		host=t.substr(0,idx);
		path=t.substr(idx);
		if((idx=path.find('?')) != std::string::npos) {
			query=path.substr(idx);
			path=path.substr(0,idx);
		}
		pv.push_back(path);
	}
	hv.push_back(host);
	// generate additional variants for host & pathes
	generateHostVariants(host,hv);
	generatePathVariants(path,pv);
	
	for(StringVector::iterator hi=hv.begin(); hi != hv.end(); ++hi) {
		tv.push_back(*hi+"/");
		if(pv.size()>0 && query != "")
			tv.push_back(*hi+pv[0]+query);
		for(StringVector::iterator pi=pv.begin(); pi != pv.end(); ++pi) {
			tv.push_back(*hi+*pi);
		}
	}
		
	StringVector::iterator it=tv.begin();
	StringVector::iterator itEnd=tv.end();
	for(; it != itEnd; ++it) {
		boost::md5 m(it->begin(),it->end());
		tm=boost::lexical_cast<std::string>(m);
		sv.push_back(tm);
#ifdef DEBUG
		std::cerr << "hash for " << *it << " = " << tm  << std::endl;
#endif
	}

	return sv.size() > 0;
}



int main(int argc, char** argv) {
	//read settings

	//
	HashFile bh;
	bh.fname="black-hash.dat";
	bh.url="black hash url";
	
	HashFile mh;
	mh.fname="malware-hash.dat";
	mh.url="malware hash url";

	std::string url;
	StringVector sv;
	const int MaxCount=10;
	int count=MaxCount;
	while(true) {
		std::getline(std::cin,url);
#ifdef DEBUG
		std::cerr << "get " << url << " from std::cin" << std::endl;
#endif
		if(count >= MaxCount) {
			mh.updateHash();
			bh.updateHash();
		}
		if(bh.h.minorVersion == -1 && mh.h.minorVersion == -1) { 
			std::cout << "" << std::endl;
			continue;
		}
		if(!generateVariants(url,sv)) {
			std::cout << "" << std::endl;
			continue;
		}
		if(bh.checkHash(sv,url) || mh.checkHash(sv,url))
			std::cout << url << std::endl;
		else
			std::cout << "" << std::endl;
	}

	return 0;
}
