#include "redismodule.h"
#include <string>
#include <helib/helib.h>
#include <helib/EncryptedArray.h>
#include <helib/ArgMap.h>
#include <NTL/BasicThreadPool.h>
#include <helib/Ctxt.h>
#include "serializers.h"

#define FHE_PK_KEY ".fhe_public_key"
#define FHE_CONTEXT_KEY ".fhe_context"

using namespace std;

int FheSetPkCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
    if (argc != 3) return RedisModule_WrongArity(ctx);
    RedisModule_AutoMemory(ctx);

    RedisModuleCallReply *reply_context = RedisModule_Call(ctx, "SET", "cs", FHE_CONTEXT_KEY, argv[1]);

    if (RedisModule_CallReplyType(reply_context) == REDISMODULE_REPLY_ERROR) {
      return RedisModule_ReplyWithCallReply(ctx, reply_context);
    }

    RedisModuleCallReply *reply_pk = RedisModule_Call(ctx, "SET", "cs", FHE_PK_KEY, argv[2]);

    if (RedisModule_CallReplyType(reply_pk) == REDISMODULE_REPLY_ERROR) {
      return RedisModule_ReplyWithCallReply(ctx, reply_pk);
    }

    RedisModule_ReplyWithSimpleString(ctx, "OK");
    return REDISMODULE_ERR;
}

int FheSetCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
    if (argc != 3) return RedisModule_WrongArity(ctx);
    RedisModule_AutoMemory(ctx);

    RedisModuleCallReply *reply = RedisModule_Call(ctx, "SET", "ss", argv[1], argv[2]);

    if (RedisModule_CallReplyType(reply) == REDISMODULE_REPLY_ERROR) {
      return RedisModule_ReplyWithCallReply(ctx, reply);
    }

    RedisModule_ReplyWithSimpleString(ctx, "OK");
    return REDISMODULE_ERR;
}

int FheGetCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
    if (argc != 2) return RedisModule_WrongArity(ctx);
    RedisModule_AutoMemory(ctx);

    size_t len_query;
    char *query_ptr = (char *)RedisModule_StringPtrLen(argv[1], &len_query);

    string query(query_ptr, len_query);

    char *context_ptr;
    size_t len_context;

    RedisModuleCallReply *context = RedisModule_Call(ctx, "GET", "c", FHE_CONTEXT_KEY);
    if (RedisModule_CallReplyType(context) == REDISMODULE_REPLY_ERROR) {
      return RedisModule_ReplyWithCallReply(ctx, context);
    }

    context_ptr = (char *)RedisModule_CallReplyStringPtr(context, &len_context);
    if (!context_ptr)
    {
        return RedisModule_ReplyWithCallReply(ctx, context);
    }

    string context_str(context_ptr, len_context);

    std::shared_ptr<helib::Context> fhe_context = stringToContext(context_str);

    long p = fhe_context->getP();
    helib::EncryptedArray ea = fhe_context->getEA();

    char *pk_ptr;
    size_t len_pk;

    RedisModuleCallReply *pk = RedisModule_Call(ctx, "GET", "c", FHE_PK_KEY);
    if (RedisModule_CallReplyType(pk) == REDISMODULE_REPLY_ERROR) {
      return RedisModule_ReplyWithCallReply(ctx, pk);
    }

    pk_ptr = (char *)RedisModule_CallReplyStringPtr(pk, &len_pk);
    if (!pk_ptr)
    {
        return RedisModule_ReplyWithCallReply(ctx, pk);
    }

    string pk_str(pk_ptr, len_pk);

    helib::PubKey public_key = stringToPubKey(pk_str, fhe_context);

    RedisModuleCallReply *keys = RedisModule_Call(ctx, "KEYS", "c", "*");
    if (RedisModule_CallReplyType(keys) == REDISMODULE_REPLY_ERROR) {
      return RedisModule_ReplyWithCallReply(ctx, keys);
    }

    size_t keys_count = RedisModule_CallReplyLength(keys);

    RedisModuleString *key;
    RedisModuleCallReply *data_by_key;
    char *value_ptr;
    char *key_ptr;
    size_t len_value;
    size_t len_key;
    std::vector<helib::Ctxt> mask;
    mask.reserve(keys_count - 2); // так как в бд хранятся еще открытый ключ и контекст
    for (size_t i = 0; i < keys_count; i++)
    {
        key = RedisModule_CreateStringFromCallReply(
        RedisModule_CallReplyArrayElement(keys, i)
        );

        key_ptr = (char *)RedisModule_StringPtrLen(key, &len_key);
        if (!key_ptr)
        {
            return RedisModule_ReplyWithCallReply(ctx, data_by_key);
        }

        if ((strcmp(FHE_CONTEXT_KEY, key_ptr) == 0) || (strcmp(FHE_PK_KEY, key_ptr) == 0))
        {
            continue;
        }

        data_by_key = RedisModule_Call(ctx, "GET", "s", key);

        if (RedisModule_CallReplyType(data_by_key) == REDISMODULE_REPLY_ERROR) {
            return RedisModule_ReplyWithCallReply(ctx, data_by_key);
        }

        value_ptr = (char *)RedisModule_CallReplyStringPtr(data_by_key, &len_value);
        if (!value_ptr)
        {
            return RedisModule_ReplyWithCallReply(ctx, data_by_key);
        }

        string key_str(key_ptr, len_key);
        helib::Ctxt mask_entry = stringToCtxt(key_str, public_key) ; // Copy of database key
        mask_entry -= stringToCtxt(query, public_key);             // Calculate the difference
        mask_entry.power(p - 1);                       // Fermat's little theorem
        mask_entry.negate();                           // Negate the ciphertext
        mask_entry.addConstant(NTL::ZZX(1));           // 1 - mask = 0 or 1
            // Create a vector of copies of the mask
        std::vector<helib::Ctxt> rotated_masks(ea.size(), mask_entry);
        for (int i = 1; i < rotated_masks.size(); i++)
            ea.rotate(rotated_masks[i], i);             // Rotate each of the masks
        totalProduct(mask_entry, rotated_masks);      // Multiply each of the masks
        string value_str(value_ptr, len_value);
        mask_entry.multiplyBy(stringToCtxt(value_str, public_key));
        mask.push_back(mask_entry);
    }

    helib::Ctxt value = mask[0];
    for (int i = 1; i < mask.size(); i++)
        value += mask[i];

    std::string res = ctxtToString(value);

    RedisModuleString *redis_res = RedisModule_CreateString(ctx, const_cast<char*>(res.c_str()), res.length());
    RedisModule_ReplyWithString(ctx, redis_res);
    return REDISMODULE_OK;
}

extern "C" int RedisModule_OnLoad(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{

	if (RedisModule_Init(ctx, "fhe_redis", 1, REDISMODULE_APIVER_1) == REDISMODULE_ERR){
		RedisModule_Log(ctx, "warning", "unable to init module");
		return REDISMODULE_ERR;
	}

    if (RedisModule_CreateCommand(ctx,"FHE.SETPK",
        FheSetPkCommand, "write",
        0, 0, 0) == REDISMODULE_ERR)
        return REDISMODULE_ERR;

	if (RedisModule_CreateCommand(ctx,"FHE.SET",
        FheSetCommand, "write",
        0, 0, 0) == REDISMODULE_ERR)
        return REDISMODULE_ERR;

    if (RedisModule_CreateCommand(ctx,"FHE.GET",
        FheGetCommand, "readonly",
        0, 0, 0) == REDISMODULE_ERR)
        return REDISMODULE_ERR;
    return REDISMODULE_OK;
}
