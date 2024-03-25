#include <gtest/gtest.h>
#include <string>
#include <jwt-cpp/jwt.h>
#include <httplib.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <sqlite3.h>

// Declare functions from your main code
int openDatabase(sqlite3 **db);
int writeKeyToDatabase(sqlite3 *db, const std::string &keyData, int exp);
std::string fetchPrivateKeyFromDatabase(sqlite3 *db);

class MyServerTest : public ::testing::Test {
protected:
    virtual void SetUp() {
        // Setup code that will be executed before each test
        int rc = openDatabase(&db_);
        ASSERT_EQ(rc, SQLITE_OK) << "Failed to open database";
    }

    virtual void TearDown() {
        sqlite3_close(db_);
    }

    sqlite3 *db_;
};

// Test case for database interaction
TEST_F(MyServerTest, DatabaseInteraction) {
    // Write a key to the db
    std::string keyData = "test_key_data";
    int exp = 123456; // Expiration time
    int rc = writeKeyToDatabase(db_, keyData, exp);
    ASSERT_EQ(rc, SQLITE_DONE) << "Failed to write key to database";

    // Fetch the key from the database and verify it
    std::string fetchedKey = fetchPrivateKeyFromDatabase(db_);
    ASSERT_EQ(fetchedKey, keyData) << "Fetched key does not match the original key";
}

// Test case for JWT token generation
TEST_F(MyServerTest, JWTTokenGeneration) {
   
    auto token = jwt::create()
        .set_issuer("auth0")
        .set_type("JWT")
        .set_payload_claim("sample", jwt::claim(std::string("test")))
        .set_issued_at(std::chrono::system_clock::now())
        .set_expires_at(std::chrono::system_clock::now() + std::chrono::hours{24})
        .set_key_id("goodKID")
        .sign(jwt::algorithm::none{});

    // Check if token not empty
    ASSERT_FALSE(token.empty()) << "JWT token is empty";
}

// You can add more test cases for HTTP endpoint responses, etc.

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
