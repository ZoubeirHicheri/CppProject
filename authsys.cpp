#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <random>
#include <iomanip>
#include <openssl/evp.h>

using namespace std;

// User class to store user information
class User {
private:
    string username;
    string hashedPassword;
    string salt;

public:
    User(string username, string hashedPassword, string salt) 
        : username(username), hashedPassword(hashedPassword), salt(salt) {}

    string getUsername() { return username; }
    string getHashedPassword() { return hashedPassword; }
    string getSalt() { return salt; }
    
    string toString() { return username + "," + hashedPassword + "," + salt; }
    
    static User fromString(string str) {
        stringstream ss(str);
        string username, hashedPassword, salt;
        
        getline( ss, username, ',');
        getline(ss, hashedPassword, ',');
        getline(ss, salt, ',');
        
        return User(username, hashedPassword, salt);
    }
};

// Generate a random salt
string generateSalt(int length = 16) {
    const string chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./";
    
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dist(0, chars.size() - 1);
    
    string salt;
    for (int i = 0; i < length; i++) {
        salt += chars[dist(gen)];
    }
    
    return salt;
}

// Hash a password using OpenSSL 3.4 EVP_Digest API
string hashPassword(const string& password, const string& salt) {
    string saltedPassword = salt + password;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw runtime_error("Failed to create OpenSSL context");

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, saltedPassword.c_str(), saltedPassword.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        throw runtime_error("Failed to compute SHA-256 hash");
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int length = 0;

    if (EVP_DigestFinal_ex(ctx, hash, &length) != 1) {
        EVP_MD_CTX_free(ctx);
        throw runtime_error("Failed to finalize SHA-256 hash");
    }

    EVP_MD_CTX_free(ctx);

    stringstream ss;
    for (unsigned int i = 0; i < length; i++) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }

    return ss.str();
}

// Validate password strength
bool validatePassword(string password, vector<string>& errors) {
    errors.clear();
    bool isValid = true;
    
    if (password.length() < 8) {
        errors.push_back("Password must be at least 8 characters long");
        isValid = false;
    }
    
    if (none_of(password.begin(), password.end(), ::isupper)) {
        errors.push_back("Password must contain at least one uppercase letter");
        isValid = false;
    }
    
    if (none_of(password.begin(), password.end(), ::isdigit)) {
        errors.push_back("Password must contain at least one number");
        isValid = false;
    }
    
    if (none_of(password.begin(), password.end(), [](char c) { return !isalnum(c); })) {
        errors.push_back("Password must contain at least one special character");
        isValid = false;
    }
    
    return isValid;
}

// User Repository to handle file operations
class UserRepository {
private:
    string filePath;

public:
    UserRepository(string filePath) : filePath(filePath) {}
    
    void saveUser(User user) {
        ofstream file(filePath, ios::app);
        if (!file) throw runtime_error("Could not open file for writing");
        
        file << user.toString() << endl;
        file.close();
    }
    
    User findByUsername(string username) {
        ifstream file(filePath);
        if (!file) throw runtime_error("Could not open file for reading");
        
        string line;
        while (getline(file, line)) {
            User user = User::fromString(line);
            if (user.getUsername() == username) {
                file.close();
                return user;
            }
        }
        
        file.close();
        throw runtime_error("User not found");
    }
    
    bool userExists(string username) {
        try {
            findByUsername(username);
            return true;
        } catch (runtime_error&) {
            return false;
        }
    }
};

// Authentication Service to handle user operations
class AuthService {
private:
    UserRepository userRepo;

public:
    AuthService(string filePath) : userRepo(filePath) {}
    
    bool registerUser(string username, string password) {
        if (username.empty()) {
            cout << "Username cannot be empty" << endl;
            return false;
        }
        
        if (userRepo.userExists(username)) {
            cout << "Username already exists" << endl;
            return false;
        }
        
        vector<string> errors;
        if (!validatePassword(password, errors)) {
            cout << "Password validation failed:\n";
            for (const string& error : errors) {
                cout << "- " << error << endl;
            }
            return false;
        }
        
        string salt = generateSalt();
        string hashedPassword = hashPassword(password, salt);
        User user(username, hashedPassword, salt);
        userRepo.saveUser(user);
        
        return true;
    }
    
    bool login(string username, string password) {
        try {
            User user = userRepo.findByUsername(username);
            string hashedPassword = hashPassword(password, user.getSalt());
            return hashedPassword == user.getHashedPassword();
        } catch (runtime_error&) {
            return false;
        }
    }
};

// Main application
class AuthApp {
private:
    AuthService authService;

public:
    AuthApp(string filePath) : authService(filePath) {}
    
    void run() {
        cout << "===== User Authentication System =====\n";
        cout << "Using OpenSSL 3.4 for secure password hashing\n";
        
        while (true) {
            cout << "\nSelect an option:\n";
            cout << "1. Register a new user\n";
            cout << "2. Login\n";
            cout << "3. Exit\n";
            cout << "> ";
            
            int choice;
            cin >> choice;
            cin.ignore();
            
            if (choice == 1) {
                cout << "\n-- User Registration --\n";
                
                cout << "Enter username: ";
                string username;
                getline(cin, username);
                
                cout << "Enter password: ";
                string password;
                getline(cin, password);
                
                if (authService.registerUser(username, password)) {
                    cout << "User registered successfully!\n";
                } else {
                    cout << "Registration failed!\n";
                }
            } else if (choice == 2) {
                cout << "\n-- User Login --\n";
                
                cout << "Enter username: ";
                string username;
                getline(cin, username);
                
                cout << "Enter password: ";
                string password;
                getline(cin, password);
                
                if (authService.login(username, password)) {
                    cout << "Login successful!\n";
                } else {
                    cout << "Login failed: Invalid username or password\n";
                }
            } else if (choice == 3) {
                cout << "Exiting application. Goodbye!\n";
                break;
            } else {
                cout << "Invalid option. Please try again.\n";
            }
        }
    }
};

int main() {
    try {
        AuthApp app("users.txt");
        app.run();
    } catch (exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
    
    return 0;
}