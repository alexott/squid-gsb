
//          Copyright Kevin Sopp 2007.
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

// Implements 'The MD5 Message-Digest Algorithm' by R. Rivest
// RFC 1321 http://tools.ietf.org/html/rfc1321


#ifndef BOOST_MD5_HPP
#define BOOST_MD5_HPP

#include <cstdio>
#include <limits>
#include <ostream>
#include <boost/cstdint.hpp>
#include <boost/static_assert.hpp>

BOOST_STATIC_ASSERT(std::numeric_limits<unsigned char>::digits == 8);

namespace boost
{

struct md5
{
  typedef std::size_t size_type;

  md5(){}

  template<typename RandomAccessIterator>
  md5(RandomAccessIterator first, RandomAccessIterator last)
  {
    process(first, last);
  }

  md5(const void* data, size_type len)
  {
    process(data, len);
  }

  md5(const md5&);

  ~md5()
  {
    clear();
  }

  md5& operator = (const md5&);

  const unsigned char* digest() const { return msg_digest_; }

  template<typename RandomAccessIterator>
  void process(RandomAccessIterator first,
               RandomAccessIterator last, bool add = false)
  {
    process(&*first, last-first, add);
  }

  void process(const void* data, size_type len, bool add = false);

private:

  typedef boost::uint8_t  uint8;
  typedef boost::uint32_t uint32;
  typedef boost::uint64_t uint64;

  struct context
  {
    context();

    context(const context&);

    context& operator = (const context&);

    void reset();

    union
    {
      struct
      {
        uint32 a, b, c, d;
      };
      uint32 state[4];
    };
    uint64 num_bits;
    uint8 buffer[64];
  };

  // resets internal context
  void clear();

  void process(context& c, const uint8* msg) const;

  // auxiliary functions
  struct aux_f
  {
    uint32 operator()(uint32 x, uint32 y, uint32 z) { return (x & y)|(~x & z); }
  };
  struct aux_g
  {
    uint32 operator()(uint32 x, uint32 y, uint32 z) { return (x & z)|(y & ~z); }
  };
  struct aux_h
  {
    uint32 operator()(uint32 x, uint32 y, uint32 z) { return x ^ y ^ z;        }
  };
  struct aux_i
  {
    uint32 operator()(uint32 x, uint32 y, uint32 z) { return y ^ (x | ~z);     }
  };

  static uint32 left_rotate(uint32 x, uint32 num_bits)
  {
    return (x << num_bits) | (x >> (32-num_bits));
  }

  template<typename AuxFunctor>
  static void transform(uint32& a, uint32 b, uint32 c, uint32 d,
                        uint32 k, uint32 s, uint32 i)
  {
    a = b + left_rotate(a + AuxFunctor()(b,c,d) + k + i, s);
  }

  void store_msg_digest(const context&);

  context ctx_, ctx_backup_;
  uint8 msg_digest_[16];
};

bool operator == (const md5& lhs, const md5& rhs);
bool operator != (const md5& lhs, const md5& rhs);
bool operator == (const md5& m, const char* digest);
bool operator != (const md5& m, const char* digest);
bool operator == (const char* digest, const md5& m);
bool operator != (const char* digest, const md5& m);

template<typename charT, class traits>
std::basic_ostream<charT, traits>&
operator << (std::basic_ostream<charT, traits>& out, const md5& m)
{
  char buf[40];
  for (int i = 0; i < 16; ++i)
    std::sprintf(buf+i*2, "%02x", m.digest()[i]);
  return out << buf;
}



} // namespace boost

#endif

