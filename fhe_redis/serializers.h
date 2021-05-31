#ifndef FHE_SERIALIZERS_H
#define FHE_SERIALIZERS_H

#include <helib/helib.h>
#include <helib/Ctxt.h>
#include <string>

helib::Ctxt stringToCtxt(const std::string& str, const helib::PubKey &pkp);

std::string ctxtToString(const helib::Ctxt& ctxt);

std::string contextToString(const helib::Context& context);

std::shared_ptr<helib::Context> stringToContext(const std::string& str);

helib::PubKey stringToPubKey(const std::string& pk_str, std::shared_ptr<helib::Context> context);

std::string pubKeyToString(const helib::PubKey& pk);

#endif