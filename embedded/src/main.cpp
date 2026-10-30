#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <deque>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace {
using Bytes = std::vector<unsigned char>;
using Clock = std::chrono::steady_clock;
constexpr std::size_t SHA256_BYTES = 32;
constexpr std::int64_t STEP_SECONDS = 60;
constexpr char INFO[] = "embedded-otp-v2|";

struct Session { std::string user; Bytes salt; Bytes id; };
void wipe(Bytes& value) { if (!value.empty()) { OPENSSL_cleanse(value.data(), value.size()); value.clear(); } }
void wipe(std::string& value) { if (!value.empty()) { OPENSSL_cleanse(value.data(), value.size()); value.clear(); } }
Bytes bytes(const std::string& value) { return Bytes(value.begin(), value.end()); }
Bytes random_bytes(std::size_t size) { Bytes out(size); if (RAND_bytes(out.data(), static_cast<int>(size)) != 1) throw std::runtime_error("Secure random generation failed."); return out; }

Bytes hmac(const Bytes& key, const Bytes& data) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> buffer{}; unsigned int length = 0;
    if (!HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data.data(), data.size(), buffer.data(), &length) || length != SHA256_BYTES) throw std::runtime_error("HMAC failed.");
    Bytes result(buffer.begin(), buffer.begin() + length); OPENSSL_cleanse(buffer.data(), buffer.size()); return result;
}
Bytes digest(const Bytes& data) {
    std::array<unsigned char, SHA256_BYTES> result{}; unsigned int length = 0; EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    const bool failed = !ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 || EVP_DigestUpdate(ctx, data.data(), data.size()) != 1 || EVP_DigestFinal_ex(ctx, result.data(), &length) != 1;
    EVP_MD_CTX_free(ctx); if (failed || length != SHA256_BYTES) throw std::runtime_error("SHA-256 failed."); return Bytes(result.begin(), result.end());
}
Bytes hkdf(const Bytes& master, const Bytes& salt, const Bytes& info) {
    Bytes actual_salt = salt.empty() ? Bytes(SHA256_BYTES, 0) : salt; Bytes prk = hmac(actual_salt, master); Bytes block_input = info; block_input.push_back(1); Bytes out = hmac(prk, block_input);
    wipe(actual_salt); wipe(prk); wipe(block_input); return out;
}
std::array<unsigned char, 8> counter_bytes(std::int64_t value) { std::array<unsigned char, 8> out{}; for (int i=7;i>=0;--i) out[static_cast<std::size_t>(i)] = static_cast<unsigned char>((static_cast<std::uint64_t>(value) >> ((7-i)*8)) & 0xff); return out; }
std::int64_t current_step() { return static_cast<std::int64_t>(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now())) / STEP_SECONDS; }
Bytes context(const Session& s) { Bytes out=bytes(std::string(INFO)+s.user+"|"); out.insert(out.end(),s.id.begin(),s.id.end()); return out; }
std::string otp(const Bytes& master, const Session& s, std::int64_t step) {
    Bytes info=context(s), key=hkdf(master,s.salt,info); wipe(info); auto counter=counter_bytes(step); Bytes message(counter.begin(),counter.end()), mac=hmac(key,message); wipe(key); wipe(message);
    unsigned offset=mac.back()&0x0f; if(offset+4>mac.size()) { wipe(mac); throw std::runtime_error("Invalid OTP truncation."); }
    std::uint32_t value=(static_cast<std::uint32_t>(mac[offset]&0x7f)<<24)|(static_cast<std::uint32_t>(mac[offset+1])<<16)|(static_cast<std::uint32_t>(mac[offset+2])<<8)|mac[offset+3]; wipe(mac);
    std::ostringstream out; out<<std::setw(6)<<std::setfill('0')<<(value%1000000U); return out.str();
}
bool equal(const std::string& a,const std::string& b) { return a.size()==b.size() && CRYPTO_memcmp(a.data(),b.data(),a.size())==0; }
bool otp_format(const std::string& value) { return value.size()==6 && std::all_of(value.begin(),value.end(),[](unsigned char c){return std::isdigit(c)!=0;}); }
std::string anchor(const Session& s) { static constexpr char chars[]="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"; Bytes hash=digest(s.id); std::string out; for(int i=0;i<4;++i) out+=chars[hash[i]%36]; wipe(hash); return out; }
std::string fingerprint(const Bytes& master,const Session& s,const std::string& entered,std::int64_t step) { Bytes input=s.id; input.insert(input.end(),entered.begin(),entered.end()); auto c=counter_bytes(step); input.insert(input.end(),c.begin(),c.end()); Bytes mac=hmac(master,input); wipe(input); std::ostringstream out; for(auto b:mac) out<<std::hex<<std::setw(2)<<std::setfill('0')<<static_cast<int>(b); wipe(mac); return out.str(); }
void log(const std::string& user,const std::string& result) { std::ofstream file("authentication.log",std::ios::app); if(file) file<<std::time(nullptr)<<" user="<<user<<" result="<<result<<'\n'; }

class Protection {
    struct Failures { int consecutive=0; std::deque<Clock::time_point> times; Clock::time_point retry{}; Clock::time_point locked{}; };
    std::unordered_map<std::string,Failures> failures_; std::unordered_map<std::string,Clock::time_point> used_;
    void cleanup() { auto now=Clock::now(); for(auto it=used_.begin();it!=used_.end();) { if(it->second<=now) it=used_.erase(it); else ++it; } }
public:
    std::optional<std::string> blocked(const std::string& user) { cleanup(); auto it=failures_.find(user); if(it==failures_.end()) return {}; auto now=Clock::now(); if(now<it->second.locked) return "Account locked for repeated failures."; if(now<it->second.retry) return "Backoff active: wait before requesting another OTP."; return {}; }
    bool used(const std::string& item) { cleanup(); return used_.find(item) != used_.end(); }
    void accept(const std::string& user,const std::string& item) { used_[item]=Clock::now()+std::chrono::seconds(STEP_SECONDS*2); failures_.erase(user); }
    std::string fail(const std::string& user) { auto now=Clock::now(); auto& f=failures_[user]; f.times.push_back(now); while(!f.times.empty() && now-f.times.front()>std::chrono::minutes(5)) f.times.pop_front(); int seconds=1<<std::min(f.consecutive++,5); f.retry=now+std::chrono::seconds(seconds); if(f.times.size()>=3) { f.locked=now+std::chrono::minutes(5); f.consecutive=0; f.times.clear(); return "Account locked for 5 minutes after 3 failures."; } return "Progressive backoff: wait "+std::to_string(seconds)+" second(s)."; }
};

Bytes pbkdf2(const std::string& pass,const Bytes& salt) { Bytes key(32); if(PKCS5_PBKDF2_HMAC(pass.c_str(),static_cast<int>(pass.size()),salt.data(),static_cast<int>(salt.size()),600000,EVP_sha256(),32,key.data())!=1) throw std::runtime_error("PBKDF2 failed."); return key; }
std::string passphrase(const char* prompt) { const char* env=std::getenv("OTP_KEY_PASSPHRASE"); if(env&&*env) return env; std::cout<<prompt; std::string pass; std::getline(std::cin,pass); if(pass.size()<12) throw std::runtime_error("Passphrase must be 12+ characters."); return pass; }
// AES-GCM secret-file implementation, kept separate to retain the authentication tag.
Bytes encrypt_secret(const Bytes& plain,const std::string& pass) {
    Bytes salt=random_bytes(16),iv=random_bytes(12),key=pbkdf2(pass,salt),cipher(plain.size()); std::array<unsigned char,16>tag{}; int n=0,last=0; EVP_CIPHER_CTX* c=EVP_CIPHER_CTX_new();
    bool bad=!c||EVP_EncryptInit_ex(c,EVP_aes_256_gcm(),nullptr,nullptr,nullptr)!=1||EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_IVLEN,12,nullptr)!=1||EVP_EncryptInit_ex(c,nullptr,nullptr,key.data(),iv.data())!=1||EVP_EncryptUpdate(c,cipher.data(),&n,plain.data(),static_cast<int>(plain.size()))!=1||EVP_EncryptFinal_ex(c,cipher.data()+n,&last)!=1||EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_GET_TAG,16,tag.data())!=1; EVP_CIPHER_CTX_free(c); wipe(key); if(bad) throw std::runtime_error("AES-GCM encryption failed."); cipher.resize(n+last); Bytes out({'H','K','D','F','O','T','P','1'}); out.insert(out.end(),salt.begin(),salt.end()); out.insert(out.end(),iv.begin(),iv.end()); out.insert(out.end(),tag.begin(),tag.end()); out.insert(out.end(),cipher.begin(),cipher.end()); wipe(salt);wipe(iv);wipe(cipher);return out;
}
Bytes decrypt_secret(const Bytes& data,const std::string& pass) {
    if(data.size()<=52||!std::equal(data.begin(),data.begin()+8,"HKDFOTP1")) throw std::runtime_error("Invalid encrypted secret file."); Bytes salt(data.begin()+8,data.begin()+24),iv(data.begin()+24,data.begin()+36),key=pbkdf2(pass,salt),plain(data.size()-52); int n=0,last=0; EVP_CIPHER_CTX*c=EVP_CIPHER_CTX_new(); bool ok=c&&EVP_DecryptInit_ex(c,EVP_aes_256_gcm(),nullptr,nullptr,nullptr)==1&&EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_IVLEN,12,nullptr)==1&&EVP_DecryptInit_ex(c,nullptr,nullptr,key.data(),iv.data())==1&&EVP_DecryptUpdate(c,plain.data(),&n,data.data()+52,static_cast<int>(data.size()-52))==1&&EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_TAG,16,const_cast<unsigned char*>(data.data()+36))==1&&EVP_DecryptFinal_ex(c,plain.data()+n,&last)==1; EVP_CIPHER_CTX_free(c);wipe(salt);wipe(iv);wipe(key);if(!ok){wipe(plain);throw std::runtime_error("Wrong passphrase or modified secret file.");}plain.resize(n+last);return plain;
}
void create_secret(const std::string& path) { Bytes secret=random_bytes(32);std::string p=passphrase("Create passphrase: "),confirm;std::cout<<"Confirm passphrase: ";std::getline(std::cin,confirm);if(!equal(p,confirm)){wipe(secret);wipe(p);wipe(confirm);throw std::runtime_error("Passphrases do not match.");}Bytes encrypted=encrypt_secret(secret,p);std::ofstream file(path,std::ios::binary);file.write(reinterpret_cast<char*>(encrypted.data()),static_cast<std::streamsize>(encrypted.size()));wipe(secret);wipe(encrypted);wipe(p);wipe(confirm);if(!file)throw std::runtime_error("Could not write secret file.");std::cout<<"Encrypted secret created: "<<path<<'\n'; }
std::optional<Bytes> master(int argc,char**argv) { for(int i=1;i<argc;++i){std::string a=argv[i];if(a=="--demo-secret")return bytes("CLASSROOM-DEMO-SECRET-NOT-FOR-PRODUCTION-CHANGE-ME");if(a=="--encrypted-secret"&&i+1<argc){std::ifstream file(argv[++i],std::ios::binary);Bytes data((std::istreambuf_iterator<char>(file)),{});if(!file&&data.empty())throw std::runtime_error("Could not read encrypted secret.");std::string p=passphrase("Secret-file passphrase: ");Bytes out=decrypt_secret(data,p);wipe(data);wipe(p);return out;}}const char*env=std::getenv("OTP_MASTER_SECRET");if(env&&std::string(env).size()>=32)return bytes(env);return {}; }
}

int main(int argc,char**argv) { try { if(argc==3&&std::string(argv[1])=="--create-encrypted-secret"){create_secret(argv[2]);return 0;}auto loaded=master(argc,argv);if(!loaded){std::cerr<<"Set OTP_MASTER_SECRET, use --encrypted-secret <file>, or use --demo-secret for class only.\n";return 2;}Bytes secret=std::move(*loaded);Protection protection;std::cout<<"=== HKDF Secure OTP Authentication ===\n";for(;;){std::cout<<"\nUsername (q to quit): ";std::string user;std::getline(std::cin,user);if(user=="q"||user=="Q")break;if(user.empty()||user.size()>64){std::cout<<"Username must be 1-64 characters.\n";continue;}if(auto reason=protection.blocked(user)){std::cout<<"OTP generation denied: "<<*reason<<'\n';continue;}Session s{user,random_bytes(32),random_bytes(16)};auto issued=current_step();std::string code=otp(secret,s,issued);std::cout<<"OTP generated successfully: "<<code<<"\nVerification anchor: "<<anchor(s)<<"\nEnter OTP: ";std::string entered;std::getline(std::cin,entered);bool success=false;if(otp_format(entered)){auto now=current_step();for(auto step:{now,now-1}){auto token=fingerprint(secret,s,entered,step);if(protection.used(token)){std::cout<<"Authentication denied: OTP replay detected.\n";break;}if(equal(entered,otp(secret,s,step))){protection.accept(user,token);std::cout<<"Authentication successful. Access granted.\n";log(user,step==now?"success-current":"success-previous");success=true;break;}}}if(!success){std::cout<<"Authentication denied. "<<protection.fail(user)<<'\n';log(user,"failed");}wipe(s.salt);wipe(s.id);}wipe(secret);return 0;}catch(const std::exception&e){std::cerr<<"Fatal error: "<<e.what()<<'\n';return 1;}}
