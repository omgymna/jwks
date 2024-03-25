#include <iostream>
#include <string>
#include <jwt-cpp/jwt.h>
#include <httplib.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <sqlite3.h>

std::string bignum_to_raw_string(const BIGNUM *bn)
{
    int bn_size = BN_num_bytes(bn);
    std::string raw(bn_size, 0);
    BN_bn2bin(bn, reinterpret_cast<unsigned char *>(&raw[0]));
    return raw;
}

std::string extract_pub_key(EVP_PKEY *pkey)
{
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, pkey);
    char *data = NULL;
    long len = BIO_get_mem_data(bio, &data);
    std::string result(data, len);
    BIO_free(bio);
    return result;
}

std::string extract_priv_key(EVP_PKEY *pkey)
{
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);
    char *data = NULL;
    long len = BIO_get_mem_data(bio, &data);
    std::string result(data, len);
    BIO_free(bio);
    return result;
}

// Function to open or create SQLite database
int openDatabase(sqlite3 **db) {
    int rc = sqlite3_open("totally_not_my_privateKeys.db", db);
    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(*db));
        return rc;
    } else {
        fprintf(stdout, "Opened database successfully\n");
        return SQLITE_OK;
    }
}

// Function to write private key to the database
int writeKeyToDatabase(sqlite3 *db, const std::string &keyData, int exp) {
    const char *sql = "INSERT INTO keys (key, exp) VALUES (?, ?);";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        return rc;
    }
    
    sqlite3_bind_blob(stmt, 1, keyData.data(), keyData.size(), SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, exp);
    
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Execution failed: %s\n", sqlite3_errmsg(db));
    }
    
    sqlite3_finalize(stmt);
    return rc;
}
std::string base64_url_encode(const std::string &data)
{
    static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    for (size_t n = 0; n < data.size(); n++)
    {
        char_array_3[i++] = data[n];
        if (i == 3)
        {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; (i < 4); i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i)
    {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; (j < i + 1); j++)
            ret += base64_chars[char_array_4[j]];
    }

    // Replace '+' with '-', '/' with '_' and remove '='
    std::replace(ret.begin(), ret.end(), '+', '-');
    std::replace(ret.begin(), ret.end(), '/', '_');
    ret.erase(std::remove(ret.begin(), ret.end(), '='), ret.end());

    return ret;
}
// Function to fetch private key from SQLite database
std::string fetchPrivateKeyFromDatabase(sqlite3 *db) {
    const char *sql = "SELECT key FROM keys ORDER BY kid DESC LIMIT 1;";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        return "";
    }

    std::string privateKey;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const void *data = sqlite3_column_blob(stmt, 0);
        int dataSize = sqlite3_column_bytes(stmt, 0);
        privateKey.assign(reinterpret_cast<const char *>(data), dataSize);
    }

    sqlite3_finalize(stmt);
    return privateKey;
}

int main()
{
    // Generate RSA key pair
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);

    std::string pub_key = extract_pub_key(pkey);
    std::string priv_key = extract_priv_key(pkey);

    sqlite3 *db;
    int rc = openDatabase(&db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }

    // Write private key to the database
  
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to write private key to database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }

    // Start HTTP server
    httplib::Server svr;

    svr.Post("/auth", [&](const httplib::Request &req, httplib::Response &res)
             {
        if (req.method != "POST") {
            res.status = 405;  // Method Not Allowed
            res.set_content("Method Not Allowed", "text/plain");
            return;
        }
        // Check if the "expired" query parameter is set to "true"
        bool expired = req.has_param("expired") && req.get_param_value("expired") == "true";
        
        // Create JWT token
        auto now = std::chrono::system_clock::now();
        auto token = jwt::create()
            .set_issuer("auth0")
            .set_type("JWT")
            .set_payload_claim("sample", jwt::claim(std::string("test")))
            .set_issued_at(std::chrono::system_clock::now())
            .set_expires_at(expired ? now - std::chrono::seconds{1} : now + std::chrono::hours{24})
            .set_key_id(expired ? "expiredKID" : "goodKID")
            .sign(jwt::algorithm::rs256(pub_key, priv_key));

        res.set_content(token, "text/plain"); });

    svr.Get("/.well-known/jwks.json", [&](const httplib::Request &, httplib::Response &res)
            {
        BIGNUM* n = NULL;
        BIGNUM* e = NULL;

        if (!EVP_PKEY_get_bn_param(pkey, "n", &n) || !EVP_PKEY_get_bn_param(pkey, "e", &e)) {
            res.set_content("Error retrieving JWKS", "text/plain");
            return;
        }

        std::string n_encoded = base64_url_encode(bignum_to_raw_string(n));
        std::string e_encoded = base64_url_encode(bignum_to_raw_string(e));

        BN_free(n);
        BN_free(e);

        std::string jwks = R"({
            "keys": [
                {
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "goodKID",
                    "n": ")" + n_encoded + R"(",
                    "e": ")" + e_encoded + R"("
                }
            ]
        })";
        res.set_content(jwks, "application/json"); });

    // Catch-all handlers for other methods
    auto methodNotAllowedHandler = [](const httplib::Request &req, httplib::Response &res)
    {
        if (req.path == "/auth" || req.path == "/.well-known/jwks.json")
        {
            res.status = 405;
            res.set_content("Method Not Allowed", "text/plain");
        }
        else
        {
            res.status = 404;
            res.set_content("Not Found", "text/plain");
        }
    };

    svr.Get(".*", methodNotAllowedHandler);
    svr.Post(".*", methodNotAllowedHandler);
    svr.Put(".*", methodNotAllowedHandler);
    svr.Delete(".*", methodNotAllowedHandler);
    svr.Patch(".*", methodNotAllowedHandler);

    svr.listen("127.0.0.1", 8080);

    // Cleanup
    EVP_PKEY_free(pkey);
    sqlite3_close(db);

    return 0;

}
