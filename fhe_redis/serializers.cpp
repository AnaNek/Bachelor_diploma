#include "serializers.h"

helib::Ctxt stringToCtxt(const std::string& str, const helib::PubKey &pkp) {
    std::istringstream iss(str);
    helib::Ctxt ctxt(pkp);
    ctxt.read(iss);
    return ctxt;
}

std::string ctxtToString(const helib::Ctxt& ctxt) {
    std::ostringstream oss;
    ctxt.writeTo(oss);
    return oss.str();
}

std::string contextToString(const helib::Context& context) {
    std::ostringstream oss;
    context.writeTo(oss);
    return oss.str();
}

std::shared_ptr<helib::Context> stringToContext(const std::string& str) {
    std::istringstream iss(str);
    return (std::shared_ptr<helib::Context>)helib::Context::readPtrFrom(iss);
}

helib::PubKey stringToPubKey(const std::string& pk_str, std::shared_ptr<helib::Context> context) {
    std::istringstream pk_iss(pk_str);
    helib::PubKey pk = helib::PubKey::readFrom(pk_iss, *context);
    return pk;
}

std::string pubKeyToString(const helib::PubKey& pk) {
    std::ostringstream oss;
    pk.writeTo(oss);
    return oss.str();
}