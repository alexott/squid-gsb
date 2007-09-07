
//          Copyright Kevin Sopp 2007.
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include <cstring>
#include <boost/md5.hpp>


namespace boost
{

md5::md5(const md5& copy)
:
  ctx_(copy.ctx_),
  ctx_backup_(copy.ctx_backup_)
{
  std::memcpy(msg_digest_, copy.msg_digest_, 16);
}

md5& md5::operator = (const md5& rhs)
{
  ctx_ = rhs.ctx_;
  ctx_backup_ = rhs.ctx_backup_;
  std::memcpy(msg_digest_, rhs.msg_digest_, 16);
  return *this;
}

void md5::process(const void* vdata, size_type len, bool add)
{
  const uint8* data = reinterpret_cast<const uint8*>(vdata);
  if (add)
    ctx_ = ctx_backup_;
  
  size_type index = 0;                             // index into data array
  size_type bytes_in_buf = ctx_.num_bits / 8 % 64; // bytes in ctx.buffer

  // process any bytes that may still be left in the context from a previous
  // invocation
  if (bytes_in_buf)
  {
    const size_type bytes_to_copy =
      len > 64 - bytes_in_buf ? 64 - bytes_in_buf : len;
    std::memcpy(ctx_.buffer + bytes_in_buf, data, bytes_to_copy);
    index += bytes_to_copy;
    ctx_.num_bits += bytes_to_copy * 8;
    if (len + bytes_in_buf >= 64)
    {
      process(ctx_, ctx_.buffer);
      ctx_.num_bits += (len-index)*8;
      bytes_in_buf = 0;
    }
    else
      bytes_in_buf += bytes_to_copy;
  }
  else
    ctx_.num_bits += len * 8;

  // now process the data in 64 byte chunks
  for (; len - index >= 64; index += 64)
    process(ctx_, data + index);

  const size_type remaining_bytes = len - index;

  // backup the context and copy the remaining bytes over so that we can pick up
  // where we left off if this function gets called with add=true again
  ctx_backup_ = ctx_;
  std::memcpy(ctx_backup_.buffer, &data[index], remaining_bytes);

  // now add the padding and store the message digest
  uint8 padding[64] = {0};
  
  if (bytes_in_buf)
    std::memcpy(padding, ctx_.buffer, bytes_in_buf);

  std::memcpy(padding + bytes_in_buf, data + index, remaining_bytes);
  padding[bytes_in_buf + remaining_bytes] = 0x80;
  if (remaining_bytes >= 56)
  {
    process(ctx_, padding);
    std::memset(padding, 0, 64);
  }

  // store num_bits in little endian format
  for (int i = 0; i < 8; ++i)
    padding[56+i] = (ctx_.num_bits >> 8 * i) & 0xff;

  process(ctx_, padding);
  store_msg_digest(ctx_);
  ctx_.reset();
}

void md5::clear()
{
  ctx_.reset();
  ctx_backup_.reset();
}

// processes one chunk of 64 bytes 
void md5::process(context& ctx, const uint8* msg) const
{
  // store msg in x buffer in little endian format
  uint32 x[16];
  for (int i = 0, j = 0; i < 16; ++i, j+=4)
    x[i] =  (uint32)msg[j  ]        |
           ((uint32)msg[j+1] <<  8) |
           ((uint32)msg[j+2] << 16) |
           ((uint32)msg[j+3] << 24);

  uint32 a = ctx.a;
  uint32 b = ctx.b;
  uint32 c = ctx.c;
  uint32 d = ctx.d;

  // round 1
  transform<aux_f>(a, b, c, d, x[ 0],  7, 0xd76aa478);
  transform<aux_f>(d, a, b, c, x[ 1], 12, 0xe8c7b756);
  transform<aux_f>(c, d, a, b, x[ 2], 17, 0x242070db);
  transform<aux_f>(b, c, d, a, x[ 3], 22, 0xc1bdceee);
  transform<aux_f>(a, b, c, d, x[ 4],  7, 0xf57c0faf);
  transform<aux_f>(d, a, b, c, x[ 5], 12, 0x4787c62a);
  transform<aux_f>(c, d, a, b, x[ 6], 17, 0xa8304613);
  transform<aux_f>(b, c, d, a, x[ 7], 22, 0xfd469501);
  transform<aux_f>(a, b, c, d, x[ 8],  7, 0x698098d8);
  transform<aux_f>(d, a, b, c, x[ 9], 12, 0x8b44f7af);
  transform<aux_f>(c, d, a, b, x[10], 17, 0xffff5bb1);
  transform<aux_f>(b, c, d, a, x[11], 22, 0x895cd7be);
  transform<aux_f>(a, b, c, d, x[12],  7, 0x6b901122);
  transform<aux_f>(d, a, b, c, x[13], 12, 0xfd987193);
  transform<aux_f>(c, d, a, b, x[14], 17, 0xa679438e);
  transform<aux_f>(b, c, d, a, x[15], 22, 0x49b40821);

  // round 2
  transform<aux_g>(a, b, c, d, x[ 1],  5, 0xf61e2562);
  transform<aux_g>(d, a, b, c, x[ 6],  9, 0xc040b340);
  transform<aux_g>(c, d, a, b, x[11], 14, 0x265e5a51);
  transform<aux_g>(b, c, d, a, x[ 0], 20, 0xe9b6c7aa);
  transform<aux_g>(a, b, c, d, x[ 5],  5, 0xd62f105d);
  transform<aux_g>(d, a, b, c, x[10],  9,  0x2441453);
  transform<aux_g>(c, d, a, b, x[15], 14, 0xd8a1e681);
  transform<aux_g>(b, c, d, a, x[ 4], 20, 0xe7d3fbc8);
  transform<aux_g>(a, b, c, d, x[ 9],  5, 0x21e1cde6);
  transform<aux_g>(d, a, b, c, x[14],  9, 0xc33707d6);
  transform<aux_g>(c, d, a, b, x[ 3], 14, 0xf4d50d87);
  transform<aux_g>(b, c, d, a, x[ 8], 20, 0x455a14ed);
  transform<aux_g>(a, b, c, d, x[13],  5, 0xa9e3e905);
  transform<aux_g>(d, a, b, c, x[ 2],  9, 0xfcefa3f8);
  transform<aux_g>(c, d, a, b, x[ 7], 14, 0x676f02d9);
  transform<aux_g>(b, c, d, a, x[12], 20, 0x8d2a4c8a);
  
  // round 3
  transform<aux_h>(a, b, c, d, x[ 5],  4, 0xfffa3942);
  transform<aux_h>(d, a, b, c, x[ 8], 11, 0x8771f681);
  transform<aux_h>(c, d, a, b, x[11], 16, 0x6d9d6122);
  transform<aux_h>(b, c, d, a, x[14], 23, 0xfde5380c);
  transform<aux_h>(a, b, c, d, x[ 1],  4, 0xa4beea44);
  transform<aux_h>(d, a, b, c, x[ 4], 11, 0x4bdecfa9);
  transform<aux_h>(c, d, a, b, x[ 7], 16, 0xf6bb4b60);
  transform<aux_h>(b, c, d, a, x[10], 23, 0xbebfbc70);
  transform<aux_h>(a, b, c, d, x[13],  4, 0x289b7ec6);
  transform<aux_h>(d, a, b, c, x[ 0], 11, 0xeaa127fa);
  transform<aux_h>(c, d, a, b, x[ 3], 16, 0xd4ef3085);
  transform<aux_h>(b, c, d, a, x[ 6], 23,  0x4881d05);
  transform<aux_h>(a, b, c, d, x[ 9],  4, 0xd9d4d039);
  transform<aux_h>(d, a, b, c, x[12], 11, 0xe6db99e5);
  transform<aux_h>(c, d, a, b, x[15], 16, 0x1fa27cf8);
  transform<aux_h>(b, c, d, a, x[ 2], 23, 0xc4ac5665);
  
  // round 4
  transform<aux_i>(a, b, c, d, x[ 0],  6, 0xf4292244);
  transform<aux_i>(d, a, b, c, x[ 7], 10, 0x432aff97);
  transform<aux_i>(c, d, a, b, x[14], 15, 0xab9423a7);
  transform<aux_i>(b, c, d, a, x[ 5], 21, 0xfc93a039);
  transform<aux_i>(a, b, c, d, x[12],  6, 0x655b59c3);
  transform<aux_i>(d, a, b, c, x[ 3], 10, 0x8f0ccc92);
  transform<aux_i>(c, d, a, b, x[10], 15, 0xffeff47d);
  transform<aux_i>(b, c, d, a, x[ 1], 21, 0x85845dd1);
  transform<aux_i>(a, b, c, d, x[ 8],  6, 0x6fa87e4f);
  transform<aux_i>(d, a, b, c, x[15], 10, 0xfe2ce6e0);
  transform<aux_i>(c, d, a, b, x[ 6], 15, 0xa3014314);
  transform<aux_i>(b, c, d, a, x[13], 21, 0x4e0811a1);
  transform<aux_i>(a, b, c, d, x[ 4],  6, 0xf7537e82);
  transform<aux_i>(d, a, b, c, x[11], 10, 0xbd3af235);
  transform<aux_i>(c, d, a, b, x[ 2], 15, 0x2ad7d2bb);
  transform<aux_i>(b, c, d, a, x[ 9], 21, 0xeb86d391);

  ctx.a += a;
  ctx.b += b;
  ctx.c += c;
  ctx.d += d;
}

// store message digest in little endian format
void md5::store_msg_digest(const context& ctx)
{
  for (int i = 0, j=0; i < 16; i += 4, ++j)
  {
    msg_digest_[i  ] =  ctx.state[j]        & 0xff;
    msg_digest_[i+1] = (ctx.state[j] >>  8) & 0xff;
    msg_digest_[i+2] = (ctx.state[j] >> 16) & 0xff;
    msg_digest_[i+3] = (ctx.state[j] >> 24) & 0xff;
  }
}


md5::context::context()
:
  a(0x67452301),
  b(0xefcdab89),
  c(0x98badcfe),
  d(0x10325476),
  num_bits(0)
{}

md5::context::context(const md5::context& copy)
:
  a(copy.a),
  b(copy.b),
  c(copy.c),
  d(copy.d),
  num_bits(copy.num_bits)
{
  std::memcpy(buffer, copy.buffer, 64);
}

md5::context& md5::context::operator = (const md5::context& rhs)
{
  a = rhs.a;
  b = rhs.b;
  c = rhs.c;
  d = rhs.d;
  num_bits = rhs.num_bits;
  std::memcpy(buffer, rhs.buffer, 64);
  return *this;
}

void md5::context::reset()
{
  a = 0x67452301;
  b = 0xefcdab89;
  c = 0x98badcfe;
  d = 0x10325476;
  num_bits = 0;
  std::memset(buffer, 0, 64);
}


bool operator == (const md5& lhs, const md5& rhs)
{
  return !std::memcmp(lhs.digest(), rhs.digest(), 16);
}

bool operator != (const md5& lhs, const md5& rhs)
{
  return std::memcmp(lhs.digest(), rhs.digest(), 16);
}

bool operator == (const md5& m, const char* digest)
{
  char buf[32];
  for (int i = 0; i < 16; ++i)
    std::sprintf(buf+i*2, "%02x", m.digest()[i]);
  return !std::memcmp(buf, digest, 32);
}

bool operator != (const md5& m, const char* digest)
{
  return !(m == digest);
}

bool operator == (const char* digest, const md5& m)
{
  return m == digest;
}

bool operator != (const char* digest, const md5& m)
{
  return m != digest;
}


} // namespace boost


