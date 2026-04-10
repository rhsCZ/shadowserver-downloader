#include <curl/curl.h>
#include <openssl/hmac.h>
#include <sqlite3.h>

#include "json.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <thread>
#include <unordered_set>
#include <unistd.h>
#include <utility>
#include <vector>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace {

constexpr const char* kApiBaseUrl = "https://transform.shadowserver.org/api2";
constexpr const char* kDownloadBaseUrl = "https://dl.shadowserver.org/";
constexpr const char* kConfigPath = "/etc/shadowserver/config.conf";
constexpr const char* kDatabasePath = "/var/shadowserver-reports.db";

struct Config {
    std::string api_key;
    std::string secret;
    std::string log_path;
    std::string download_path;
    std::string database_path = kDatabasePath;
    std::chrono::milliseconds delay{0};
};

struct Options {
    std::string date_filter;
    bool show_help = false;
    bool clean_db = false;
    std::optional<std::string> remove_id_date;
    std::optional<std::string> api_key;
    std::optional<std::string> secret;
    std::optional<std::string> log_path;
    std::optional<std::string> download_path;
    std::optional<std::string> database_path;
    std::optional<std::chrono::milliseconds> delay;
};

struct HttpResponse {
    long status_code = 0;
    std::string body;
    std::string content_disposition;
};

struct ReportEntry {
    std::string id;
    std::string reported_at;
    std::string file_name;
};

class Logger {
  public:
    explicit Logger(std::string path) : path_(std::move(path)), enabled_(!path_.empty()) {
        if (enabled_) {
            stream_.open(path_, std::ios::app);
        }
    }

    void Info(const std::string& message) { Write("INFO", message); }
    void Error(const std::string& message) { Write("ERROR", message); }
    bool Enabled() const { return enabled_ && stream_.is_open(); }

  private:
    void Write(const char* level, const std::string& message) {
        if (!enabled_) {
            return;
        }
        std::ostringstream line;
        line << CurrentTimestamp() << " [" << level << "] " << message << '\n';
        if (!stream_.is_open()) {
            return;
        }
        stream_ << line.str();
        stream_.flush();
    }

    static std::string CurrentTimestamp() {
        const auto now = std::chrono::system_clock::now();
        const auto time = std::chrono::system_clock::to_time_t(now);
        std::tm tm{};
        localtime_r(&time, &tm);

        std::ostringstream oss;
        oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
        return oss.str();
    }

    std::string path_;
    bool enabled_ = false;
    std::ofstream stream_;
};

class SqliteDb {
  public:
    explicit SqliteDb(const std::string& path) {
        if (sqlite3_open(path.c_str(), &db_) != SQLITE_OK) {
            throw std::runtime_error("Failed to open SQLite database: " + ErrorMessage());
        }

        Exec("CREATE TABLE IF NOT EXISTS reports ("
             "id TEXT PRIMARY KEY,"
             "reported_at TEXT NOT NULL"
             ");");

        MigrateLegacyTable();
    }

    ~SqliteDb() {
        if (db_ != nullptr) {
            sqlite3_close(db_);
        }
    }

    bool ContainsId(const std::string& report_id) {
        sqlite3_stmt* stmt = nullptr;
        Prepare("SELECT COUNT(1) FROM reports WHERE id = ?1;", &stmt);

        BindText(stmt, 1, report_id);
        const int rc = sqlite3_step(stmt);
        if (rc != SQLITE_ROW) {
            sqlite3_finalize(stmt);
            throw std::runtime_error("SQLite SELECT failed: " + ErrorMessage());
        }

        const bool exists = sqlite3_column_int(stmt, 0) > 0;
        sqlite3_finalize(stmt);
        return exists;
    }

    int ClearReports() {
        sqlite3_stmt* stmt = nullptr;
        Prepare("DELETE FROM reports;", &stmt);
        const int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) {
            throw std::runtime_error("SQLite DELETE failed: " + ErrorMessage());
        }
        return sqlite3_changes(db_);
    }

    int RemoveById(const std::string& report_id) {
        sqlite3_stmt* stmt = nullptr;
        Prepare("DELETE FROM reports WHERE id = ?1;", &stmt);
        BindText(stmt, 1, report_id);
        const int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) {
            throw std::runtime_error("SQLite DELETE failed: " + ErrorMessage());
        }
        return sqlite3_changes(db_);
    }

    int RemoveByDate(const std::string& reported_at) {
        sqlite3_stmt* stmt = nullptr;
        Prepare("DELETE FROM reports WHERE reported_at = ?1;", &stmt);
        BindText(stmt, 1, reported_at);
        const int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) {
            throw std::runtime_error("SQLite DELETE failed: " + ErrorMessage());
        }
        return sqlite3_changes(db_);
    }

    int RemoveByDateRange(const std::string& from_date, const std::string& to_date) {
        sqlite3_stmt* stmt = nullptr;
        Prepare("DELETE FROM reports WHERE reported_at >= ?1 AND reported_at <= ?2;", &stmt);
        BindText(stmt, 1, from_date);
        BindText(stmt, 2, to_date);
        const int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) {
            throw std::runtime_error("SQLite DELETE failed: " + ErrorMessage());
        }
        return sqlite3_changes(db_);
    }

    void InsertReport(const std::string& report_id, const std::string& reported_at) {
        InsertReportImpl(report_id, reported_at, false);
    }

  private:
    void InsertReportIgnore(const std::string& report_id, const std::string& reported_at) {
        InsertReportImpl(report_id, reported_at, true);
    }

    void InsertReportImpl(const std::string& report_id, const std::string& reported_at, bool ignore_if_exists) {
        sqlite3_stmt* stmt = nullptr;
        Prepare(ignore_if_exists ? "INSERT OR IGNORE INTO reports(id, reported_at) VALUES(?1, ?2);"
                                 : "INSERT INTO reports(id, reported_at) VALUES(?1, ?2);",
                &stmt);

        BindText(stmt, 1, report_id);
        BindText(stmt, 2, reported_at);

        const int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) {
            throw std::runtime_error("SQLite INSERT failed: " + ErrorMessage());
        }
    }

    void Exec(const std::string& sql) {
        char* err = nullptr;
        const int rc = sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err);
        if (rc != SQLITE_OK) {
            std::string message = err != nullptr ? err : "unknown SQL error";
            sqlite3_free(err);
            throw std::runtime_error(message);
        }
    }

    void Prepare(const std::string& sql, sqlite3_stmt** stmt) {
        if (sqlite3_prepare_v2(db_, sql.c_str(), -1, stmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error("SQLite prepare failed: " + ErrorMessage());
        }
    }

    void BindText(sqlite3_stmt* stmt, int index, const std::string& value) {
        if (sqlite3_bind_text(stmt, index, value.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK) {
            throw std::runtime_error("SQLite bind failed: " + ErrorMessage());
        }
    }

    std::string ErrorMessage() const {
        return db_ != nullptr ? sqlite3_errmsg(db_) : "database is not initialized";
    }

    bool TableExists(const std::string& table_name) {
        sqlite3_stmt* stmt = nullptr;
        Prepare("SELECT COUNT(1) FROM sqlite_master WHERE type = 'table' AND name = ?1;", &stmt);
        BindText(stmt, 1, table_name);

        const int rc = sqlite3_step(stmt);
        if (rc != SQLITE_ROW) {
            sqlite3_finalize(stmt);
            throw std::runtime_error("SQLite SELECT failed: " + ErrorMessage());
        }

        const bool exists = sqlite3_column_int(stmt, 0) > 0;
        sqlite3_finalize(stmt);
        return exists;
    }

    void MigrateLegacyTable() {
        if (!TableExists("downloaded_reports")) {
            return;
        }

        sqlite3_stmt* stmt = nullptr;
        Prepare("SELECT id, downloaded_at, local_path FROM downloaded_reports;", &stmt);

        int rc = SQLITE_OK;
        while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
            const auto* id_text = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            const auto* downloaded_at_text = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            const auto* local_path_text = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
            if (id_text == nullptr || downloaded_at_text == nullptr) {
                continue;
            }

            InsertReportIgnore(id_text, InferReportedAt(downloaded_at_text, local_path_text != nullptr ? local_path_text : ""));
        }

        if (rc != SQLITE_DONE) {
            sqlite3_finalize(stmt);
            throw std::runtime_error("SQLite migration failed: " + ErrorMessage());
        }

        sqlite3_finalize(stmt);
        Exec("DROP TABLE downloaded_reports;");
    }

    static std::string InferReportedAt(const std::string& downloaded_at, const std::string& local_path) {
        static const std::regex date_prefix(R"(^(\d{4}-\d{2}-\d{2}))");
        const std::string filename = fs::path(local_path).filename().string();
        std::smatch match;
        if (std::regex_search(filename, match, date_prefix)) {
            return match[1].str();
        }
        return downloaded_at;
    }

    sqlite3* db_ = nullptr;
};

class CurlHandle {
  public:
    CurlHandle() {
        handle_ = curl_easy_init();
        if (handle_ == nullptr) {
            throw std::runtime_error("curl_easy_init failed.");
        }
    }

    ~CurlHandle() {
        if (handle_ != nullptr) {
            curl_easy_cleanup(handle_);
        }
    }

    CURL* get() { return handle_; }

  private:
    CURL* handle_ = nullptr;
};

std::string Trim(std::string value) {
    const auto not_space = [](unsigned char c) { return !std::isspace(c); };

    value.erase(value.begin(), std::find_if(value.begin(), value.end(), not_space));
    value.erase(std::find_if(value.rbegin(), value.rend(), not_space).base(), value.end());
    return value;
}

std::chrono::milliseconds ParseDelay(const std::string& value) {
    static const std::regex pattern(R"(^([0-9]+(?:\.[0-9]+)?)(ms|s|m|h)$)");
    std::smatch match;
    const std::string trimmed = Trim(value);
    if (!std::regex_match(trimmed, match, pattern)) {
        throw std::runtime_error("Invalid delay value: " + value + ". Use a number followed by h, m, s, or ms.");
    }

    const double amount = std::stod(match[1].str());
    const std::string unit = match[2].str();
    double milliseconds = amount;
    if (unit == "h") {
        milliseconds *= 60.0 * 60.0 * 1000.0;
    } else if (unit == "m") {
        milliseconds *= 60.0 * 1000.0;
    } else if (unit == "s") {
        milliseconds *= 1000.0;
    }

    if (milliseconds < 0.0) {
        throw std::runtime_error("Invalid delay value: " + value);
    }
    return std::chrono::milliseconds(static_cast<long long>(milliseconds));
}

Config LoadConfig(const std::string& path) {
    std::ifstream file(path);
    if (!file) {
        return Config{};
    }

    Config config;
    std::string line;
    while (std::getline(file, line)) {
        line = Trim(line);
        if (line.empty() || line[0] == '#' || line[0] == ';') {
            continue;
        }

        const auto pos = line.find('=');
        if (pos == std::string::npos) {
            continue;
        }

        const std::string key = Trim(line.substr(0, pos));
        const std::string value = Trim(line.substr(pos + 1));

        if (key == "api-key" || key == "api_key" || key == "apikey") {
            config.api_key = value;
        } else if (key == "secret" || key == "api-secret" || key == "api_secret") {
            config.secret = value;
        } else if (key == "logfile" || key == "log_file" || key == "log-path" || key == "log_path") {
            config.log_path = value;
        } else if (key == "download_path" || key == "download-path") {
            config.download_path = value;
        } else if (key == "database_path" || key == "database-path") {
            config.database_path = value;
        } else if (key == "delay") {
            config.delay = ParseDelay(value);
        }
    }
    return config;
}

void ValidateApiConfig(const Config& config) {
    if (config.api_key.empty()) {
        throw std::runtime_error("Missing api-key in configuration.");
    }
    if (config.secret.empty()) {
        throw std::runtime_error("Missing secret in configuration.");
    }
}

bool IsIsoDate(const std::string& value) {
    static const std::regex pattern(R"(^\d{4}-\d{2}-\d{2}$)");
    return std::regex_match(value, pattern);
}

bool IsEuDate(const std::string& value) {
    static const std::regex pattern(R"(^\d{2}-\d{2}-\d{4}$)");
    return std::regex_match(value, pattern);
}

std::string NormalizeSingleDate(const std::string& value) {
    if (IsIsoDate(value)) {
        return value;
    }
    if (IsEuDate(value)) {
        return value.substr(6, 4) + "-" + value.substr(3, 2) + "-" + value.substr(0, 2);
    }
    throw std::runtime_error("Invalid date format: " + value + ". Use YYYY-MM-DD or DD-MM-YYYY.");
}

std::string TodayDate() {
    const auto now = std::chrono::system_clock::now();
    const auto time = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    localtime_r(&time, &tm);

    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d");
    return oss.str();
}

std::string NormalizeDateRange(const std::string& value) {
    const auto separator = value.find(':');
    if (separator == std::string::npos || value.find(':', separator + 1) != std::string::npos) {
        throw std::runtime_error("Invalid date range format: " + value + ". Use YYYY-MM-DD:YYYY-MM-DD or DD-MM-YYYY:DD-MM-YYYY.");
    }

    const std::string from = NormalizeSingleDate(value.substr(0, separator));
    const std::string to = NormalizeSingleDate(value.substr(separator + 1));
    return from + ":" + to;
}

bool LooksLikeDateRange(const std::string& value) {
    return value.find(':') != std::string::npos;
}

std::optional<std::string> TryNormalizeSingleDate(const std::string& value) {
    try {
        if (LooksLikeDateRange(value)) {
            return std::nullopt;
        }
        return NormalizeSingleDate(value);
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

std::optional<std::pair<std::string, std::string>> TryNormalizeDateRange(const std::string& value) {
    try {
        if (!LooksLikeDateRange(value)) {
            return std::nullopt;
        }
        const std::string normalized = NormalizeDateRange(value);
        const auto separator = normalized.find(':');
        return std::make_pair(normalized.substr(0, separator), normalized.substr(separator + 1));
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

fs::path ResolveExecutableDir(const char* argv0) {
    std::array<char, 4096> buffer{};
    const ssize_t len = readlink("/proc/self/exe", buffer.data(), buffer.size() - 1);
    if (len > 0) {
        buffer[static_cast<std::size_t>(len)] = '\0';
        return fs::path(buffer.data()).parent_path();
    }

    if (argv0 != nullptr && *argv0 != '\0') {
        return fs::absolute(fs::path(argv0)).parent_path();
    }

    return fs::current_path();
}

void PrintHelp(std::ostream& os, std::string_view program_name) {
    os << "Usage: " << program_name
       << " [--date DATE] [--from-date DATE] [--from-to-date DATE:DATE] [--clean-db] [--remove-id-date VALUE] [--help|-h]\n"
       << '\n'
       << "The program calls Shadowserver reports/list, downloads new reports, and stores successfully downloaded IDs in SQLite.\n"
       << '\n'
       << "Arguments:\n"
       << "  --date VALUE          Single day. Accepts YYYY-MM-DD and DD-MM-YYYY.\n"
       << "  --from-date VALUE     Range from the specified day up to today. Accepts YYYY-MM-DD and DD-MM-YYYY.\n"
       << "  --from-to-date VALUE  Range in DATE:DATE format, where DATE is YYYY-MM-DD or DD-MM-YYYY.\n"
       << "  --clean-db            Deletes all records from the database and exits.\n"
       << "  --remove-id-date VAL  Deletes records by ID, date, or date range and exits.\n"
       << "  --api-key VALUE       Overrides api-key from configuration.\n"
       << "  --secret VALUE        Overrides secret from configuration.\n"
       << "  --logfile VALUE       Overrides logfile from configuration.\n"
       << "  --download-path VALUE Overrides download_path from configuration.\n"
       << "  --database-path VALUE Overrides database_path from configuration.\n"
       << "  --delay VALUE         Overrides delay from configuration.\n"
       << "  --help, -h            Shows this help message.\n"
       << '\n'
       << "Fixed paths:\n"
       << "  configuration: " << kConfigPath << '\n'
       << "  database:      " << kDatabasePath << '\n'
       << '\n'
       << "Configuration format is name=value, supported keys:\n"
       << "  api-key=<API_KEY>\n"
       << "  secret=<API_SECRET>\n"
       << "  logfile=/path/to/logfile.log\n"
       << "  download_path=/path/to/directory\n"
       << "  database_path=/path/to/database.db\n"
       << "  delay=0.5s\n"
       << '\n'
       << "If download_path is not set, reports are stored in the directory containing the program binary.\n"
       << "If logfile is not set, the program does not log anything.\n"
       << "If database_path is not set, " << kDatabasePath << " is used.\n"
       << "Delay units: h, m, s, ms.\n";
}

Options ParseArgs(int argc, char** argv) {
    Options options;
    options.date_filter = TodayDate();
    int date_mode_count = 0;
    int maintenance_mode_count = 0;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            options.show_help = true;
            continue;
        }

        if (arg == "--clean-db") {
            options.clean_db = true;
            ++maintenance_mode_count;
            continue;
        }

        if (arg == "--remove-id-date") {
            if (i + 1 >= argc) {
                throw std::runtime_error("Missing value after argument " + arg);
            }
            options.remove_id_date = argv[++i];
            ++maintenance_mode_count;
            continue;
        }

        if (arg == "--api-key" || arg == "--secret" || arg == "--logfile" ||
            arg == "--download-path" || arg == "--database-path" || arg == "--delay") {
            if (i + 1 >= argc) {
                throw std::runtime_error("Missing value after argument " + arg);
            }

            const std::string value = argv[++i];
            if (arg == "--api-key") {
                options.api_key = value;
            } else if (arg == "--secret") {
                options.secret = value;
            } else if (arg == "--logfile") {
                options.log_path = value;
            } else if (arg == "--download-path") {
                options.download_path = value;
            } else if (arg == "--database-path") {
                options.database_path = value;
            } else {
                options.delay = ParseDelay(value);
            }
            continue;
        }

        if (arg == "--date" || arg == "--from-date" || arg == "--from-to-date") {
            if (i + 1 >= argc) {
                throw std::runtime_error("Missing value after argument " + arg);
            }

            const std::string value = argv[++i];
            ++date_mode_count;
            if (date_mode_count > 1) {
                throw std::runtime_error("Arguments --date, --from-date, and --from-to-date are mutually exclusive.");
            }

            if (arg == "--date") {
                if (value.find(':') != std::string::npos) {
                    throw std::runtime_error("Argument --date accepts only a single date.");
                }
                options.date_filter = NormalizeSingleDate(value);
            } else if (arg == "--from-date") {
                if (value.find(':') != std::string::npos) {
                    throw std::runtime_error("Argument --from-date accepts only a single date.");
                }
                options.date_filter = NormalizeSingleDate(value) + ":" + TodayDate();
            } else {
                if (value.find(':') == std::string::npos) {
                    throw std::runtime_error("Argument --from-to-date accepts only a date range.");
                }
                options.date_filter = NormalizeDateRange(value);
            }
            continue;
        }

        throw std::runtime_error("Unknown argument: " + arg);
    }

    if (maintenance_mode_count > 1) {
        throw std::runtime_error("Arguments --clean-db and --remove-id-date are mutually exclusive.");
    }

    if (maintenance_mode_count > 0 && date_mode_count > 0) {
        throw std::runtime_error("Arguments --clean-db and --remove-id-date cannot be combined with --date, --from-date, or --from-to-date.");
    }

    return options;
}

std::string HmacSha256Hex(const std::string& body, const std::string& secret) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;

    HMAC(EVP_sha256(),
         secret.data(),
         static_cast<int>(secret.size()),
         reinterpret_cast<const unsigned char*>(body.data()),
         body.size(),
         digest,
         &digest_len);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < digest_len; ++i) {
        oss << std::setw(2) << static_cast<int>(digest[i]);
    }
    return oss.str();
}

size_t WriteToString(void* contents, size_t size, size_t nmemb, void* userp) {
    const size_t total = size * nmemb;
    auto* output = static_cast<std::string*>(userp);
    output->append(static_cast<const char*>(contents), total);
    return total;
}

size_t HeaderToDisposition(void* contents, size_t size, size_t nmemb, void* userp) {
    const size_t total = size * nmemb;
    std::string_view header(static_cast<const char*>(contents), total);
    auto* disposition = static_cast<std::string*>(userp);

    std::string lowered(header);
    std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });

    constexpr std::string_view prefix = "content-disposition:";
    if (std::string_view(lowered).substr(0, prefix.size()) == prefix) {
        *disposition = std::string(header);
    }
    return total;
}

size_t WriteToFile(void* contents, size_t size, size_t nmemb, void* userp) {
    const size_t total = size * nmemb;
    FILE* file = static_cast<FILE*>(userp);
    return std::fwrite(contents, 1, total, file);
}

std::string ExtractFilenameFromDisposition(const std::string& header, const std::string& report_id) {
    const auto filename_pos = header.find("filename=");
    if (filename_pos == std::string::npos) {
        return "";
    }

    std::string filename = header.substr(filename_pos + 9);
    filename = Trim(filename);
    if (!filename.empty() && filename.front() == '"') {
        filename.erase(filename.begin());
    }
    while (!filename.empty() && (filename.back() == '"' || filename.back() == '\r' || filename.back() == '\n' || filename.back() == ';')) {
        filename.pop_back();
    }

    for (char& c : filename) {
        if (c == '/' || c == '\\' || c == '\0') {
            c = '_';
        }
    }

    if (filename.empty()) {
        filename = report_id + ".csv";
    }
    return filename;
}

fs::path MakeUniquePath(fs::path target) {
    if (!fs::exists(target)) {
        return target;
    }

    const std::string stem = target.stem().string();
    const std::string extension = target.extension().string();
    for (int i = 1; i < 10000; ++i) {
        fs::path candidate = target.parent_path() / (stem + "_" + std::to_string(i) + extension);
        if (!fs::exists(candidate)) {
            return candidate;
        }
    }

        throw std::runtime_error("Unable to find a free file name for " + target.string());
}

std::string BuildRequestBody(const Config& config, const std::string& date_filter) {
    json body = {
        {"date", date_filter},
        {"apikey", config.api_key},
    };
    return body.dump();
}

HttpResponse PostJson(const std::string& url, const std::string& body, const std::string& hmac) {
    CurlHandle curl;
    std::string response_body;
    char error_buffer[CURL_ERROR_SIZE] = {0};

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json, text/plain, */*");
    headers = curl_slist_append(headers, ("HMAC2: " + hmac).c_str());

    curl_easy_setopt(curl.get(), CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_POST, 1L);
    curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
    curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, WriteToString);
    curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &response_body);
    curl_easy_setopt(curl.get(), CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl.get(), CURLOPT_ERRORBUFFER, error_buffer);

    const CURLcode rc = curl_easy_perform(curl.get());
    if (rc != CURLE_OK) {
        curl_slist_free_all(headers);
        throw std::runtime_error(std::string("HTTP request failed: ") +
                                 (error_buffer[0] != '\0' ? error_buffer : curl_easy_strerror(rc)));
    }

    long status_code = 0;
    curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &status_code);
    curl_slist_free_all(headers);

    if (status_code < 200 || status_code >= 300) {
        throw std::runtime_error("HTTP status " + std::to_string(status_code) + ": " + response_body);
    }

    HttpResponse response;
    response.status_code = status_code;
    response.body = std::move(response_body);
    return response;
}

std::vector<ReportEntry> CollectReports(const json& node) {
    std::vector<ReportEntry> reports;
    std::unordered_set<std::string> seen;

    const auto recurse = [&](const auto& self, const json& value, std::vector<ReportEntry>& out) -> void {
        if (value.is_object()) {
            const auto id_it = value.find("id");
            if (id_it != value.end() && id_it->is_string()) {
                const std::string id = id_it->get<std::string>();
                if (seen.insert(id).second) {
                    ReportEntry report;
                    report.id = id;
                    if (const auto timestamp_it = value.find("timestamp"); timestamp_it != value.end() && timestamp_it->is_string()) {
                        report.reported_at = timestamp_it->get<std::string>();
                    }
                    if (const auto file_it = value.find("file"); file_it != value.end() && file_it->is_string()) {
                        report.file_name = file_it->get<std::string>();
                    }
                    out.push_back(std::move(report));
                }
            }
            for (const auto& [_, child] : value.items()) {
                self(self, child, out);
            }
            return;
        }

        if (value.is_array()) {
            for (const auto& child : value) {
                self(self, child, out);
            }
        }
    };

    recurse(recurse, node, reports);
    return reports;
}

std::vector<ReportEntry> FetchReports(const Config& config, const std::string& date_filter) {
    const std::string body = BuildRequestBody(config, date_filter);
    const std::string hmac = HmacSha256Hex(body, config.secret);
    const HttpResponse response = PostJson(std::string(kApiBaseUrl) + "/reports/list", body, hmac);

    const json parsed = json::parse(response.body);
    return CollectReports(parsed);
}

fs::path CreateTempDownloadPath(const fs::path& download_dir) {
    fs::path template_path = download_dir / ".shadowserver-report-XXXXXX.part";
    std::string path = template_path.string();
    std::vector<char> buffer(path.begin(), path.end());
    buffer.push_back('\0');

    const int fd = mkstemps(buffer.data(), 5);
    if (fd < 0) {
        throw std::runtime_error("mkstemps() failed: " + std::string(std::strerror(errno)));
    }
    close(fd);
    return fs::path(buffer.data());
}

std::string SanitizeFilename(std::string filename, const std::string& fallback_name) {
    filename = Trim(filename);
    if (filename.empty()) {
        filename = fallback_name;
    }

    for (char& c : filename) {
        if (c == '/' || c == '\\' || c == '\0') {
            c = '_';
        }
    }

    return filename;
}

fs::path DownloadReport(const ReportEntry& report, const fs::path& download_dir, Logger& logger) {
    CurlHandle curl;
    char error_buffer[CURL_ERROR_SIZE] = {0};
    std::string disposition;
    const fs::path temp_path = CreateTempDownloadPath(download_dir);

    FILE* file = std::fopen(temp_path.c_str(), "wb");
    if (file == nullptr) {
        throw std::runtime_error("Unable to open temporary file for writing: " + temp_path.string());
    }

    curl_easy_setopt(curl.get(), CURLOPT_URL, (std::string(kDownloadBaseUrl) + report.id).c_str());
    curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, WriteToFile);
    curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, file);
    curl_easy_setopt(curl.get(), CURLOPT_HEADERFUNCTION, HeaderToDisposition);
    curl_easy_setopt(curl.get(), CURLOPT_HEADERDATA, &disposition);
    curl_easy_setopt(curl.get(), CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl.get(), CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(curl.get(), CURLOPT_ERRORBUFFER, error_buffer);

    const CURLcode rc = curl_easy_perform(curl.get());
    std::fclose(file);

    if (rc != CURLE_OK) {
        fs::remove(temp_path);
        throw std::runtime_error(std::string("Downloading report ") + report.id + " failed: " +
                                 (error_buffer[0] != '\0' ? error_buffer : curl_easy_strerror(rc)));
    }

    long status_code = 0;
    curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &status_code);
    if (status_code < 200 || status_code >= 300) {
        fs::remove(temp_path);
        throw std::runtime_error("Downloading report " + report.id + " returned HTTP status " + std::to_string(status_code));
    }

    const std::string fallback_name = report.file_name.empty() ? report.id + ".csv" : report.file_name;
    const std::string filename = SanitizeFilename(ExtractFilenameFromDisposition(disposition, report.id), fallback_name);
    const fs::path final_path = MakeUniquePath(download_dir / filename);
    fs::rename(temp_path, final_path);
    logger.Info("Report " + report.id + " saved to " + final_path.string());
    return final_path;
}

void EnsureDirectoryExists(const fs::path& path) {
    std::error_code ec;
    if (fs::exists(path, ec)) {
        if (!fs::is_directory(path, ec)) {
            throw std::runtime_error("download_path does not point to a directory: " + path.string());
        }
        return;
    }

    fs::create_directories(path, ec);
    if (ec) {
        throw std::runtime_error("Unable to create download_path: " + path.string() + " (" + ec.message() + ")");
    }
}

void EnsureParentDirectoryExists(const fs::path& file_path) {
    const fs::path parent = file_path.parent_path();
    if (parent.empty()) {
        return;
    }
    std::error_code ec;
    if (fs::exists(parent, ec)) {
        if (!fs::is_directory(parent, ec)) {
            throw std::runtime_error("Logfile path does not have a valid directory: " + parent.string());
        }
        return;
    }

    fs::create_directories(parent, ec);
    if (ec) {
        throw std::runtime_error("Unable to create directory for logfile: " + parent.string() + " (" + ec.message() + ")");
    }
}

void EnsureDatabasePathReady(const fs::path& db_path) {
    EnsureParentDirectoryExists(db_path);
}

void ApplyOptionOverrides(const Options& options, Config& config) {
    if (options.api_key.has_value()) {
        config.api_key = *options.api_key;
    }
    if (options.secret.has_value()) {
        config.secret = *options.secret;
    }
    if (options.log_path.has_value()) {
        config.log_path = *options.log_path;
    }
    if (options.download_path.has_value()) {
        config.download_path = *options.download_path;
    }
    if (options.database_path.has_value()) {
        config.database_path = *options.database_path;
    }
    if (options.delay.has_value()) {
        config.delay = *options.delay;
    }
}

class CurlRuntime {
  public:
    CurlRuntime() {
        const CURLcode rc = curl_global_init(CURL_GLOBAL_DEFAULT);
        if (rc != CURLE_OK) {
            throw std::runtime_error("curl_global_init failed.");
        }
    }

    ~CurlRuntime() { curl_global_cleanup(); }
};

}  // namespace

int main(int argc, char** argv) {
    try {
        const Options options = ParseArgs(argc, argv);
        if (options.show_help) {
            PrintHelp(std::cout, argc > 0 ? argv[0] : "shadowserver-downloader");
            return 0;
        }

        Config config = LoadConfig(kConfigPath);
        ApplyOptionOverrides(options, config);
        if (config.download_path.empty()) {
            config.download_path = ResolveExecutableDir(argc > 0 ? argv[0] : nullptr).string();
        }
        if (!config.log_path.empty()) {
            EnsureParentDirectoryExists(config.log_path);
        }
        EnsureDatabasePathReady(config.database_path);

        Logger logger(config.log_path);
        logger.Info("Database path: " + config.database_path);

        SqliteDb db(config.database_path);
        if (options.clean_db) {
            const int removed = db.ClearReports();
            logger.Info("Database cleaned, removed records: " + std::to_string(removed));
            return 0;
        }

        if (options.remove_id_date.has_value()) {
            const std::string value = *options.remove_id_date;
            int removed = 0;
            if (const auto range = TryNormalizeDateRange(value); range.has_value()) {
                removed = db.RemoveByDateRange(range->first, range->second);
            } else if (const auto date = TryNormalizeSingleDate(value); date.has_value()) {
                removed = db.RemoveByDate(date.value());
            } else {
                removed = db.RemoveById(value);
            }
            logger.Info("Removed records from database: " + std::to_string(removed));
            return 0;
        }

        ValidateApiConfig(config);
        CurlRuntime curl_runtime;
        const fs::path download_dir = config.download_path;
        EnsureDirectoryExists(download_dir);
        logger.Info("Program start, date filter: " + options.date_filter);
        logger.Info("Target directory for reports: " + config.download_path);
        logger.Info("Delay between report downloads: " + std::to_string(config.delay.count()) + " ms");

        const std::vector<ReportEntry> reports = FetchReports(config, options.date_filter);

        if (reports.empty()) {
            logger.Info("reports/list returned no report IDs.");
            return 0;
        }

        int downloaded_count = 0;
        int skipped_count = 0;

        for (std::size_t i = 0; i < reports.size(); ++i) {
            const ReportEntry& report = reports[i];
            if (db.ContainsId(report.id)) {
                ++skipped_count;
                logger.Info("Report " + report.id + " is already in the database, skipping.");
                continue;
            }

            try {
                DownloadReport(report, download_dir, logger);
                db.InsertReport(report.id, report.reported_at.empty() ? options.date_filter : report.reported_at);
                ++downloaded_count;
                if (config.delay.count() > 0 && i + 1 < reports.size()) {
                    std::this_thread::sleep_for(config.delay);
                }
            } catch (const std::exception& ex) {
                logger.Error(ex.what());
            }
        }

        logger.Info("Done. Downloaded: " + std::to_string(downloaded_count) +
                    ", skipped: " + std::to_string(skipped_count) +
                    ", IDs found: " + std::to_string(reports.size()));
        (void)curl_runtime;
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << '\n';
        return 1;
    }
}
